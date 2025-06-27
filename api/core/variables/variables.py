from collections.abc import Sequence
from typing import Any, cast
from uuid import uuid4

from pydantic import BaseModel, Field

from core.helper import encrypter

from .segments import (
    ArrayAnySegment,
    ArrayFileSegment,
    ArrayNumberSegment,
    ArrayObjectSegment,
    ArraySegment,
    ArrayStringSegment,
    FileSegment,
    FloatSegment,
    IntegerSegment,
    NoneSegment,
    ObjectSegment,
    Segment,
    StringSegment,
)
from .types import SegmentType


class Variable(Segment):
    """
    A variable is a segment that has a name.
    """

    id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique identity for variable.",
    )
    name: str
    description: str = Field(default="", description="Description of the variable.")
    selector: Sequence[str] = Field(default_factory=list)


class StringVariable(StringSegment, Variable):
    pass


class FloatVariable(FloatSegment, Variable):
    pass


class IntegerVariable(IntegerSegment, Variable):
    pass


class ObjectVariable(ObjectSegment, Variable):
    pass


class ArrayVariable(ArraySegment, Variable):
    pass


class ArrayAnyVariable(ArrayAnySegment, ArrayVariable):
    pass


class ArrayStringVariable(ArrayStringSegment, ArrayVariable):
    pass


class ArrayNumberVariable(ArrayNumberSegment, ArrayVariable):
    pass


class ArrayObjectVariable(ArrayObjectSegment, ArrayVariable):
    pass


class SecretVariable(StringVariable):
    value_type: SegmentType = SegmentType.SECRET

    @property
    def log(self) -> str:
        return cast(str, encrypter.obfuscated_token(self.value))


class NoneVariable(NoneSegment, Variable):
    value_type: SegmentType = SegmentType.NONE
    value: None = None


class FileVariable(FileSegment, Variable):
    pass


class ArrayFileVariable(ArrayFileSegment, ArrayVariable):
    pass


class RAGPipelineVariable(BaseModel):
    belong_to_node_id: str = Field(description="belong to which node id, shared means public")
    type: str = Field(description="variable type, text-input, paragraph, select, number,  file, file-list")
    label: str = Field(description="label")
    description: str | None = Field(description="description", default="")
    variable: str = Field(description="variable key", default="")
    max_length: int | None = Field(
        description="max length, applicable to text-input, paragraph, and file-list", default=0
    )
    default_value: Any = Field(description="default value", default="")
    placeholder: str | None = Field(description="placeholder", default="")
    unit: str | None = Field(description="unit, applicable to Number", default="")
    tooltips: str | None = Field(description="helpful text", default="")
    allowed_file_types: list[str] | None = Field(
        description="image, document, audio, video, custom.", default_factory=list
    )
    allowed_file_extensions: list[str] | None = Field(description="e.g. ['.jpg', '.mp3']", default_factory=list)
    allowed_file_upload_methods: list[str] | None = Field(
        description="remote_url, local_file, tool_file.", default_factory=list
    )
    required: bool = Field(description="optional, default false", default=False)
    options: list[str] | None = Field(default_factory=list)


class RAGPipelineVariableInput(BaseModel):
    variable: RAGPipelineVariable
    value: Any
