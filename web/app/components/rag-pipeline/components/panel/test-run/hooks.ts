import { useTranslation } from 'react-i18next'
import type { DataSourceOption } from './types'
import { TestRunStep } from './types'
import { useNodes } from 'reactflow'
import { BlockEnum } from '@/app/components/workflow/types'
import type { DataSourceNodeType } from '@/app/components/workflow/nodes/data-source/types'
import { useCallback, useMemo, useState } from 'react'
import type { CrawlResult } from '@/models/datasets'
import { type CrawlResultItem, CrawlStep, type FileItem } from '@/models/datasets'
import produce from 'immer'
import type { NotionPage } from '@/models/common'

export const useTestRunSteps = () => {
  const { t } = useTranslation()
  const [currentStep, setCurrentStep] = useState(1)

  const handleNextStep = useCallback(() => {
    setCurrentStep(preStep => preStep + 1)
  }, [])

  const handleBackStep = useCallback(() => {
    setCurrentStep(preStep => preStep - 1)
  }, [])

  const steps = [
    {
      label: t('datasetPipeline.testRun.steps.dataSource'),
      value: TestRunStep.dataSource,
    },
    {
      label: t('datasetPipeline.testRun.steps.documentProcessing'),
      value: TestRunStep.documentProcessing,
    },
  ]

  return {
    steps,
    currentStep,
    handleNextStep,
    handleBackStep,
  }
}

export const useDatasourceOptions = () => {
  const nodes = useNodes<DataSourceNodeType>()
  const datasourceNodes = nodes.filter(node => node.data.type === BlockEnum.DataSource)

  const options = useMemo(() => {
    const options: DataSourceOption[] = []
    datasourceNodes.forEach((node) => {
      const label = node.data.title
      options.push({
        label,
        value: node.id,
        data: node.data,
      })
    })
    if (process.env.NODE_ENV === 'development') {
      // todo: delete mock data
      options.push({
        label: 'Google Drive',
        value: '123456',
        // @ts-expect-error mock data
        data: {
          datasource_parameters: {},
          datasource_configurations: {},
          type: BlockEnum.DataSource,
          title: 'Google Drive',
          plugin_id: 'langgenius/google-drive',
          provider_type: 'online_drive',
          provider_name: 'google_drive',
          datasource_name: 'google-drive',
          datasource_label: 'Google Drive',
          selected: false,
        },
      })
    }
    return options
  }, [datasourceNodes])

  return options
}

export const useLocalFile = () => {
  const [fileList, setFileList] = useState<FileItem[]>([])

  const allFileLoaded = useMemo(() => (fileList.length > 0 && fileList.every(file => file.file.id)), [fileList])

  const updateFile = (fileItem: FileItem, progress: number, list: FileItem[]) => {
    const newList = produce(list, (draft) => {
      const targetIndex = draft.findIndex(file => file.fileID === fileItem.fileID)
      draft[targetIndex] = {
        ...draft[targetIndex],
        progress,
      }
    })
    setFileList(newList)
  }

  const updateFileList = (preparedFiles: FileItem[]) => {
    setFileList(preparedFiles)
  }

  return {
    fileList,
    allFileLoaded,
    updateFile,
    updateFileList,
  }
}

export const useOnlineDocuments = () => {
  const [onlineDocuments, setOnlineDocuments] = useState<NotionPage[]>([])

  const updateOnlineDocuments = (value: NotionPage[]) => {
    setOnlineDocuments(value)
  }

  return {
    onlineDocuments,
    updateOnlineDocuments,
  }
}

export const useWebsiteCrawl = () => {
  const [websitePages, setWebsitePages] = useState<CrawlResultItem[]>([])
  const [crawlResult, setCrawlResult] = useState<CrawlResult | undefined>()
  const [step, setStep] = useState<CrawlStep>(CrawlStep.init)

  return {
    crawlResult,
    setCrawlResult,
    websitePages,
    setWebsitePages,
    step,
    setStep,
  }
}
