import * as echarts from 'echarts/core';

export const terminalTheme = {
  color: [
    '#39ff88', // accent
    '#6b7686', // dim
    '#ff3b4e', // critical
    '#ff8a3d', // high
    '#f5c542', // medium
    '#4da3ff', // low
  ],
  backgroundColor: 'transparent',
  textStyle: {
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: 10,
    color: '#6b7686',
  },
  title: {
    textStyle: { color: '#c9d1d9', fontSize: 11, fontWeight: 'normal' },
    subtextStyle: { color: '#6b7686' },
  },
  line: {
    itemStyle: { borderWidth: 1 },
    lineStyle: { width: 1 },
    symbolSize: 0,
    symbol: 'none',
    smooth: false,
  },
  bar: {
    itemStyle: {
      barBorderWidth: 0,
      barBorderColor: '#1c2430',
      borderRadius: 0, // strictly no rounded corners
    },
  },
  pie: {
    itemStyle: {
      borderWidth: 1,
      borderColor: '#0d1117',
    },
  },
  scatter: {
    itemStyle: { borderWidth: 0 },
  },
  boxplot: {
    itemStyle: { borderWidth: 1 },
  },
  parallel: {
    itemStyle: { borderWidth: 1 },
  },
  sankey: {
    itemStyle: { borderWidth: 1 },
  },
  funnel: {
    itemStyle: { borderWidth: 1 },
  },
  gauge: {
    itemStyle: { borderWidth: 1 },
  },
  candlestick: {
    itemStyle: {
      color: '#39ff88',
      color0: '#ff3b4e',
      borderColor: '#39ff88',
      borderColor0: '#ff3b4e',
      borderWidth: 1,
    },
  },
  graph: {
    itemStyle: { borderWidth: 0, borderColor: '#1c2430' },
    lineStyle: { width: 1, color: '#1c2430' },
    symbolSize: 4,
    symbol: 'rect',
    smooth: false,
    color: ['#39ff88', '#6b7686', '#ff3b4e'],
    label: { color: '#c9d1d9' },
  },
  map: {
    itemStyle: {
      areaColor: '#1c2430',
      borderColor: '#6b7686',
      borderWidth: 0.5,
    },
    label: { color: '#c9d1d9' },
    emphasis: {
      itemStyle: { areaColor: '#39ff88', borderColor: '#0d1117' },
      label: { color: '#0a0c10' },
    },
  },
  categoryAxis: {
    axisLine: { show: true, lineStyle: { color: '#1c2430', width: 1 } },
    axisTick: { show: true, lineStyle: { color: '#1c2430', width: 1 } },
    axisLabel: { show: true, color: '#6b7686' },
    splitLine: { show: false },
    splitArea: { show: false },
  },
  valueAxis: {
    axisLine: { show: true, lineStyle: { color: '#1c2430', width: 1 } },
    axisTick: { show: false },
    axisLabel: { show: true, color: '#6b7686' },
    splitLine: { show: true, lineStyle: { color: '#1c2430', width: 1, type: 'dashed' } },
    splitArea: { show: false },
  },
  logAxis: {
    axisLine: { show: true, lineStyle: { color: '#1c2430', width: 1 } },
    axisTick: { show: true, lineStyle: { color: '#1c2430', width: 1 } },
    axisLabel: { show: true, color: '#6b7686' },
    splitLine: { show: true, lineStyle: { color: '#1c2430', width: 1 } },
    splitArea: { show: false },
  },
  timeAxis: {
    axisLine: { show: true, lineStyle: { color: '#1c2430', width: 1 } },
    axisTick: { show: true, lineStyle: { color: '#1c2430', width: 1 } },
    axisLabel: { show: true, color: '#6b7686' },
    splitLine: { show: true, lineStyle: { color: '#1c2430', width: 1, type: 'dashed' } },
    splitArea: { show: false },
  },
  toolbox: {
    iconStyle: { borderColor: '#6b7686' },
    emphasis: { iconStyle: { borderColor: '#39ff88' } },
  },
  legend: {
    textStyle: { color: '#c9d1d9' },
  },
  tooltip: {
    axisPointer: {
      lineStyle: { color: '#39ff88', width: 1 },
      crossStyle: { color: '#39ff88', width: 1 },
    },
    backgroundColor: '#0d1117',
    borderColor: '#1c2430',
    borderWidth: 1,
    padding: 8,
    textStyle: { color: '#c9d1d9', fontSize: 11, fontFamily: "'JetBrains Mono', monospace" },
  },
  dataZoom: {
    backgroundColor: 'rgba(0,0,0,0)',
    dataBackgroundColor: '#1c2430',
    fillerColor: 'rgba(57,255,136,0.1)',
    handleColor: '#39ff88',
    handleSize: '100%',
    textStyle: { color: '#6b7686' },
  },
  markPoint: {
    label: { color: '#c9d1d9' },
    emphasis: { label: { color: '#c9d1d9' } },
  },
};

export function registerTheme() {
  echarts.registerTheme('terminal', terminalTheme);
}
