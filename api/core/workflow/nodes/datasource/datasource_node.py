from collections.abc import Generator, Mapping, Sequence
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.datasource.entities.datasource_entities import (
    DatasourceMessage,
    DatasourceParameter,
    DatasourceProviderType,
    GetOnlineDocumentPageContentRequest,
)
from core.datasource.online_document.online_document_plugin import OnlineDocumentDatasourcePlugin
from core.datasource.utils.message_transformer import DatasourceFileMessageTransformer
from core.file import File
from core.file.enums import FileTransferMethod, FileType
from core.plugin.impl.exc import PluginDaemonClientSideError
from core.variables.segments import ArrayAnySegment
from core.variables.variables import ArrayAnyVariable
from core.workflow.entities.node_entities import NodeRunResult
from core.workflow.entities.variable_pool import VariablePool, VariableValue
from core.workflow.entities.workflow_node_execution import WorkflowNodeExecutionStatus
from core.workflow.enums import SystemVariableKey
from core.workflow.nodes.base import BaseNode
from core.workflow.nodes.enums import NodeType
from core.workflow.nodes.event.event import RunCompletedEvent, RunStreamChunkEvent
from core.workflow.nodes.tool.exc import ToolFileError
from core.workflow.utils.variable_template_parser import VariableTemplateParser
from extensions.ext_database import db
from factories import file_factory
from models.model import UploadFile
from services.datasource_provider_service import DatasourceProviderService

from ...entities.workflow_node_execution import WorkflowNodeExecutionMetadataKey
from .entities import DatasourceNodeData
from .exc import DatasourceNodeError, DatasourceParameterError


class DatasourceNode(BaseNode[DatasourceNodeData]):
    """
    Datasource Node
    """

    _node_data_cls = DatasourceNodeData
    _node_type = NodeType.DATASOURCE

    def _run(self) -> Generator:
        """
        Run the datasource node
        """

        node_data = cast(DatasourceNodeData, self.node_data)
        variable_pool = self.graph_runtime_state.variable_pool
        datasource_type = variable_pool.get(["sys", SystemVariableKey.DATASOURCE_TYPE.value])
        if not datasource_type:
            raise DatasourceNodeError("Datasource type is not set")
        datasource_type = datasource_type.value
        datasource_info = variable_pool.get(["sys", SystemVariableKey.DATASOURCE_INFO.value])
        if not datasource_info:
            raise DatasourceNodeError("Datasource info is not set")
        datasource_info = datasource_info.value
        # get datasource runtime
        try:
            from core.datasource.datasource_manager import DatasourceManager

            if datasource_type is None:
                raise DatasourceNodeError("Datasource type is not set")

            datasource_runtime = DatasourceManager.get_datasource_runtime(
                provider_id=f"{node_data.plugin_id}/{node_data.provider_name}",
                datasource_name=node_data.datasource_name or "",
                tenant_id=self.tenant_id,
                datasource_type=DatasourceProviderType.value_of(datasource_type),
            )
        except DatasourceNodeError as e:
            yield RunCompletedEvent(
                run_result=NodeRunResult(
                    status=WorkflowNodeExecutionStatus.FAILED,
                    inputs={},
                    metadata={WorkflowNodeExecutionMetadataKey.DATASOURCE_INFO: datasource_info},
                    error=f"Failed to get datasource runtime: {str(e)}",
                    error_type=type(e).__name__,
                )
            )

        # get parameters
        datasource_parameters = datasource_runtime.entity.parameters
        parameters = self._generate_parameters(
            datasource_parameters=datasource_parameters,
            variable_pool=variable_pool,
            node_data=self.node_data,
        )
        parameters_for_log = self._generate_parameters(
            datasource_parameters=datasource_parameters,
            variable_pool=variable_pool,
            node_data=self.node_data,
            for_log=True,
        )

        try:
            match datasource_type:
                case DatasourceProviderType.ONLINE_DOCUMENT:
                    datasource_runtime = cast(OnlineDocumentDatasourcePlugin, datasource_runtime)
                    datasource_provider_service = DatasourceProviderService()
                    credentials = datasource_provider_service.get_real_datasource_credentials(
                        tenant_id=self.tenant_id,
                        provider=node_data.provider_name,
                        plugin_id=node_data.plugin_id,
                    )
                    if credentials:
                        datasource_runtime.runtime.credentials = credentials[0].get("credentials")
                    online_document_result: Generator[DatasourceMessage, None, None] = (
                        datasource_runtime.get_online_document_page_content(
                            user_id=self.user_id,
                            datasource_parameters=GetOnlineDocumentPageContentRequest(
                                workspace_id=datasource_info.get("workspace_id"),
                                page_id=datasource_info.get("page").get("page_id"),
                                type=datasource_info.get("page").get("type"),
                            ),
                            provider_type=datasource_type,
                        )
                    )
                    yield from self._transform_message(
                        messages=online_document_result,
                        parameters_for_log=parameters_for_log,
                        datasource_info=datasource_info,
                    )

                case DatasourceProviderType.WEBSITE_CRAWL:
                    yield RunCompletedEvent(
                        run_result=NodeRunResult(
                            status=WorkflowNodeExecutionStatus.SUCCEEDED,
                            inputs=parameters_for_log,
                            metadata={WorkflowNodeExecutionMetadataKey.DATASOURCE_INFO: datasource_info},
                            outputs={
                                **datasource_info,
                                "datasource_type": datasource_type,
                            },
                        )
                    )
                case DatasourceProviderType.LOCAL_FILE:
                    related_id = datasource_info.get("related_id")
                    if not related_id:
                        raise DatasourceNodeError("File is not exist")
                    upload_file = db.session.query(UploadFile).filter(UploadFile.id == related_id).first()
                    if not upload_file:
                        raise ValueError("Invalid upload file Info")

                    file_info = File(
                        id=upload_file.id,
                        filename=upload_file.name,
                        extension="." + upload_file.extension,
                        mime_type=upload_file.mime_type,
                        tenant_id=self.tenant_id,
                        type=FileType.CUSTOM,
                        transfer_method=FileTransferMethod.LOCAL_FILE,
                        remote_url=upload_file.source_url,
                        related_id=upload_file.id,
                        size=upload_file.size,
                        storage_key=upload_file.key,
                    )
                    variable_pool.add([self.node_id, "file"], [file_info])
                    for key, value in datasource_info.items():
                        # construct new key list
                        new_key_list = ["file", key]
                        self._append_variables_recursively(
                            variable_pool=variable_pool,
                            node_id=self.node_id,
                            variable_key_list=new_key_list,
                            variable_value=value,
                        )
                    yield RunCompletedEvent(
                        run_result=NodeRunResult(
                            status=WorkflowNodeExecutionStatus.SUCCEEDED,
                            inputs=parameters_for_log,
                            metadata={WorkflowNodeExecutionMetadataKey.DATASOURCE_INFO: datasource_info},
                            outputs={
                                "file_info": datasource_info,
                                "datasource_type": datasource_type,
                            },
                        )
                    )
                case _:
                    raise DatasourceNodeError(f"Unsupported datasource provider: {datasource_type}")
        except PluginDaemonClientSideError as e:
            yield RunCompletedEvent(
                run_result=NodeRunResult(
                    status=WorkflowNodeExecutionStatus.FAILED,
                    inputs=parameters_for_log,
                    metadata={WorkflowNodeExecutionMetadataKey.DATASOURCE_INFO: datasource_info},
                    error=f"Failed to transform datasource message: {str(e)}",
                    error_type=type(e).__name__,
                )
            )
        except DatasourceNodeError as e:
            yield RunCompletedEvent(
                run_result=NodeRunResult(
                    status=WorkflowNodeExecutionStatus.FAILED,
                    inputs=parameters_for_log,
                    metadata={WorkflowNodeExecutionMetadataKey.DATASOURCE_INFO: datasource_info},
                    error=f"Failed to invoke datasource: {str(e)}",
                    error_type=type(e).__name__,
                )
            )

    def _generate_parameters(
        self,
        *,
        datasource_parameters: Sequence[DatasourceParameter],
        variable_pool: VariablePool,
        node_data: DatasourceNodeData,
        for_log: bool = False,
    ) -> dict[str, Any]:
        """
        Generate parameters based on the given tool parameters, variable pool, and node data.

        Args:
            tool_parameters (Sequence[ToolParameter]): The list of tool parameters.
            variable_pool (VariablePool): The variable pool containing the variables.
            node_data (ToolNodeData): The data associated with the tool node.

        Returns:
            Mapping[str, Any]: A dictionary containing the generated parameters.

        """
        datasource_parameters_dictionary = {parameter.name: parameter for parameter in datasource_parameters}

        result: dict[str, Any] = {}
        if node_data.datasource_parameters:
            for parameter_name in node_data.datasource_parameters:
                parameter = datasource_parameters_dictionary.get(parameter_name)
                if not parameter:
                    result[parameter_name] = None
                    continue
                datasource_input = node_data.datasource_parameters[parameter_name]
                if datasource_input.type == "variable":
                    variable = variable_pool.get(datasource_input.value)
                    if variable is None:
                        raise DatasourceParameterError(f"Variable {datasource_input.value} does not exist")
                    parameter_value = variable.value
                elif datasource_input.type in {"mixed", "constant"}:
                    segment_group = variable_pool.convert_template(str(datasource_input.value))
                    parameter_value = segment_group.log if for_log else segment_group.text
                else:
                    raise DatasourceParameterError(f"Unknown datasource input type '{datasource_input.type}'")
                result[parameter_name] = parameter_value

        return result

    def _fetch_files(self, variable_pool: VariablePool) -> list[File]:
        variable = variable_pool.get(["sys", SystemVariableKey.FILES.value])
        assert isinstance(variable, ArrayAnyVariable | ArrayAnySegment)
        return list(variable.value) if variable else []

    def _append_variables_recursively(
        self, variable_pool: VariablePool, node_id: str, variable_key_list: list[str], variable_value: VariableValue
    ):
        """
        Append variables recursively
        :param node_id: node id
        :param variable_key_list: variable key list
        :param variable_value: variable value
        :return:
        """
        variable_pool.add([node_id] + variable_key_list, variable_value)

        # if variable_value is a dict, then recursively append variables
        if isinstance(variable_value, dict):
            for key, value in variable_value.items():
                # construct new key list
                new_key_list = variable_key_list + [key]
                self._append_variables_recursively(
                    variable_pool=variable_pool, node_id=node_id, variable_key_list=new_key_list, variable_value=value
                )

    @classmethod
    def _extract_variable_selector_to_variable_mapping(
        cls,
        *,
        graph_config: Mapping[str, Any],
        node_id: str,
        node_data: DatasourceNodeData,
    ) -> Mapping[str, Sequence[str]]:
        """
        Extract variable selector to variable mapping
        :param graph_config: graph config
        :param node_id: node id
        :param node_data: node data
        :return:
        """
        result = {}
        if node_data.datasource_parameters:
            for parameter_name in node_data.datasource_parameters:
                input = node_data.datasource_parameters[parameter_name]
                if input.type == "mixed":
                    assert isinstance(input.value, str)
                    selectors = VariableTemplateParser(input.value).extract_variable_selectors()
                    for selector in selectors:
                        result[selector.variable] = selector.value_selector
                elif input.type == "variable":
                    result[parameter_name] = input.value
                elif input.type == "constant":
                    pass

            result = {node_id + "." + key: value for key, value in result.items()}

        return result

    def _transform_message(
        self,
        messages: Generator[DatasourceMessage, None, None],
        parameters_for_log: dict[str, Any],
        datasource_info: dict[str, Any],
    ) -> Generator:
        """
        Convert ToolInvokeMessages into tuple[plain_text, files]
        """
        # transform message and handle file storage
        message_stream = DatasourceFileMessageTransformer.transform_datasource_invoke_messages(
            messages=messages,
            user_id=self.user_id,
            tenant_id=self.tenant_id,
            conversation_id=None,
        )

        text = ""
        files: list[File] = []
        json: list[dict] = []

        variables: dict[str, Any] = {}

        for message in message_stream:
            if message.type in {
                DatasourceMessage.MessageType.IMAGE_LINK,
                DatasourceMessage.MessageType.BINARY_LINK,
                DatasourceMessage.MessageType.IMAGE,
            }:
                assert isinstance(message.message, DatasourceMessage.TextMessage)

                url = message.message.text
                if message.meta:
                    transfer_method = message.meta.get("transfer_method", FileTransferMethod.DATASOURCE_FILE)
                else:
                    transfer_method = FileTransferMethod.DATASOURCE_FILE

                datasource_file_id = str(url).split("/")[-1].split(".")[0]

                with Session(db.engine) as session:
                    stmt = select(UploadFile).where(UploadFile.id == datasource_file_id)
                    datasource_file = session.scalar(stmt)
                    if datasource_file is None:
                        raise ToolFileError(f"Tool file {datasource_file_id} does not exist")

                mapping = {
                    "datasource_file_id": datasource_file_id,
                    "type": file_factory.get_file_type_by_mime_type(datasource_file.mime_type),
                    "transfer_method": transfer_method,
                    "url": url,
                }
                file = file_factory.build_from_mapping(
                    mapping=mapping,
                    tenant_id=self.tenant_id,
                )
                files.append(file)
            elif message.type == DatasourceMessage.MessageType.BLOB:
                # get tool file id
                assert isinstance(message.message, DatasourceMessage.TextMessage)
                assert message.meta

                datasource_file_id = message.message.text.split("/")[-1].split(".")[0]
                with Session(db.engine) as session:
                    stmt = select(UploadFile).where(UploadFile.id == datasource_file_id)
                    datasource_file = session.scalar(stmt)
                    if datasource_file is None:
                        raise ToolFileError(f"datasource file {datasource_file_id} not exists")

                mapping = {
                    "datasource_file_id": datasource_file_id,
                    "transfer_method": FileTransferMethod.DATASOURCE_FILE,
                }

                files.append(
                    file_factory.build_from_mapping(
                        mapping=mapping,
                        tenant_id=self.tenant_id,
                    )
                )
            elif message.type == DatasourceMessage.MessageType.TEXT:
                assert isinstance(message.message, DatasourceMessage.TextMessage)
                text += message.message.text
                yield RunStreamChunkEvent(
                    chunk_content=message.message.text, from_variable_selector=[self.node_id, "text"]
                )
            elif message.type == DatasourceMessage.MessageType.JSON:
                assert isinstance(message.message, DatasourceMessage.JsonMessage)
                if self.node_type == NodeType.AGENT:
                    msg_metadata = message.message.json_object.pop("execution_metadata", {})
                    agent_execution_metadata = {
                        key: value
                        for key, value in msg_metadata.items()
                        if key in WorkflowNodeExecutionMetadataKey.__members__.values()
                    }
                json.append(message.message.json_object)
            elif message.type == DatasourceMessage.MessageType.LINK:
                assert isinstance(message.message, DatasourceMessage.TextMessage)
                stream_text = f"Link: {message.message.text}\n"
                text += stream_text
                yield RunStreamChunkEvent(chunk_content=stream_text, from_variable_selector=[self.node_id, "text"])
            elif message.type == DatasourceMessage.MessageType.VARIABLE:
                assert isinstance(message.message, DatasourceMessage.VariableMessage)
                variable_name = message.message.variable_name
                variable_value = message.message.variable_value
                if message.message.stream:
                    if not isinstance(variable_value, str):
                        raise ValueError("When 'stream' is True, 'variable_value' must be a string.")
                    if variable_name not in variables:
                        variables[variable_name] = ""
                    variables[variable_name] += variable_value

                    yield RunStreamChunkEvent(
                        chunk_content=variable_value, from_variable_selector=[self.node_id, variable_name]
                    )
                else:
                    variables[variable_name] = variable_value
            elif message.type == DatasourceMessage.MessageType.FILE:
                assert message.meta is not None
                files.append(message.meta["file"])

        yield RunCompletedEvent(
            run_result=NodeRunResult(
                status=WorkflowNodeExecutionStatus.SUCCEEDED,
                outputs={"json": json, "files": files, **variables, "text": text},
                metadata={
                    WorkflowNodeExecutionMetadataKey.DATASOURCE_INFO: datasource_info,
                },
                inputs=parameters_for_log,
            )
        )
    @classmethod
    def version(cls) -> str:
        return "1"
