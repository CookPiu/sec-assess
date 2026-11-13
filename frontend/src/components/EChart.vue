<script setup lang="ts">
import { BarChart, LineChart, PieChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { type EChartsCoreOption, type EChartsType, init, use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { onBeforeUnmount, onMounted, shallowRef, useTemplateRef, watch } from 'vue'

use([BarChart, LineChart, PieChart, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer])

const props = withDefaults(defineProps<{ option: EChartsCoreOption; height?: string }>(), { height: '260px' })

const el = useTemplateRef<HTMLDivElement>('el')
const chart = shallowRef<EChartsType | null>(null)
let observer: ResizeObserver | null = null

onMounted(() => {
  if (!el.value) return
  chart.value = init(el.value)
  chart.value.setOption(props.option)
  observer = new ResizeObserver(() => chart.value?.resize())
  observer.observe(el.value)
})

watch(
  () => props.option,
  (option) => chart.value?.setOption(option, { notMerge: true }),
)

onBeforeUnmount(() => {
  observer?.disconnect()
  chart.value?.dispose()
})
</script>

<template>
  <div ref="el" :style="{ height: props.height, width: '100%' }" />
</template>
