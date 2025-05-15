import React, { useState, useMemo } from 'react';
import { useDropzone } from 'react-dropzone';
import {
  PieChart, Pie, BarChart, Bar, LineChart, Line, AreaChart, Area,
  Cell, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer,
  ComposedChart
} from 'recharts';
import {
  Container, Paper, Typography, Button, Grid, Box,
  Dialog, DialogTitle, DialogContent, CssBaseline,
  Table, TableBody, TableCell, TableContainer, TableHead,
  TableRow, TextField, createTheme, ThemeProvider,
  Chip, LinearProgress, Tooltip, CircularProgress
} from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import InsertChartIcon from '@mui/icons-material/InsertChart';
import SearchIcon from '@mui/icons-material/Search';
import * as XLSX from 'xlsx';
import './App.css';

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: { main: '#1976d2' },
    secondary: { main: '#ff4081' },
    background: { default: '#f5f7fa' }
  },
  typography: {
    fontFamily: 'Roboto, Arial, sans-serif',
    h4: { fontWeight: 700 },
    h6: { fontWeight: 600 }
  },
});

const App = () => {
  const [filesData, setFilesData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [exportLoading, setExportLoading] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: '.pcap,.pcapng',
    maxSize: 100 * 1024 * 1024,
    onDrop: async (files) => {
      try {
        setLoading(true);
        const file = files[0];
        setSelectedFile(file);

        const formData = new FormData();
        formData.append('file', file);
        const response = await fetch('http://localhost:5000/api/analyze', {
          method: 'POST',
          body: formData,
        });

        if (!response.ok) throw new Error(`Ошибка: ${response.statusText}`);

        const data = await response.json();
        const stats = calculateStats(data);

        setFilesData([{ name: file.name, data, stats }]);
      } finally {
        setLoading(false);
      }
    },
  });

  const formatExcelDate = (timestamp) => {
    if (!timestamp) return 'N/A';
    try {
      const date = new Date(timestamp);
      return isNaN(date) ? 'N/A' : date.toLocaleString('ru-RU');
    } catch {
      return 'N/A';
    }
  };

  const calculateStats = (data) => {
    if (!data || !Array.isArray(data)) {
      return {
        totalPackets: 0,
        anomalies: 0,
        anomalyTypes: [],
        protocols: [],
        totalTraffic: 0
      };
    }

    const anomalies = data.filter(item => item.prediction === 'Anomaly');
    const anomalyTypes = anomalies.reduce((acc, item) => {
      const type = item.anomaly_details || 'Unknown';
      acc[type] = (acc[type] || 0) + 1;
      return acc;
    }, {});

    const protocols = data.reduce((acc, { protocol }) => {
      acc[protocol] = (acc[protocol] || 0) + 1;
      return acc;
    }, {});

    const totalTraffic = data.reduce((sum, item) => sum + (item.details?.bytes || 0), 0);

    const protocolRatios = Object.entries(protocols).map(([proto, count]) => ({
      proto,
      count,
      ratio: (count / data.length * 100).toFixed(2)
    }));

    return {
      totalPackets: data.length,
      anomalies: anomalies.length,
      anomalyTypes: Object.entries(anomalyTypes).map(([type, count]) => ({ type, count })),
      protocols: protocolRatios,
      totalTraffic
    };
  };

  const exportToExcel = async () => {
    if (!filesData.length || !filesData[0]?.data?.length) {
      alert('Нет данных для экспорта');
      return;
    }

    try {
      setExportLoading(true);

      const dataToExport = filteredData.map((item, index) => ({
        '#': index + 1,
        'Время': formatExcelDate(item.timestamp),
        'Источник IP': item.src_ip || 'N/A',
        'Назначение IP': item.dst_ip || 'N/A',
        'Протокол': item.protocol || 'N/A',
        'Размер (байт)': item.details?.bytes || 0,
        'Статус': item.prediction || 'N/A',
        'Тип аномалии': item.anomaly_details || 'N/A',
        'Уверенность (%)': item.confidence ? Math.round(item.confidence * 100) : 0,
        'TTL': item.details?.ttl || 'N/A'
      }));

      const wb = XLSX.utils.book_new();
      const ws = XLSX.utils.json_to_sheet(dataToExport);

      ws['!cols'] = [
        { wch: 5 }, { wch: 20 }, { wch: 15 },
        { wch: 15 }, { wch: 10 }, { wch: 12 },
        { wch: 12 }, { wch: 20 }, { wch: 12 },
        { wch: 8 }
      ];

      XLSX.utils.book_append_sheet(wb, ws, "Анализ трафика");

      const fileName = `traffic_analysis_${
        selectedFile?.name.replace(/\.[^/.]+$/, "") || 
        new Date().toISOString().slice(0, 10)
      }.xlsx`;

      XLSX.writeFile(wb, fileName);

    } catch (error) {
      console.error("Export error:", error);
      alert(`Ошибка экспорта: ${error.message}`);
    } finally {
      setExportLoading(false);
    }
  };

  const filteredData = useMemo(() => {
    if (!filesData.length || !filesData[0].data) return [];

    return filesData[0].data.filter(item => {
      if (statusFilter === 'normal' && item.prediction !== 'Normal') return false;
      if (statusFilter === 'anomaly' && item.prediction !== 'Anomaly') return false;

      const searchLower = searchTerm.toLowerCase();
      return (
        item.src_ip?.toLowerCase().includes(searchLower) ||
        item.dst_ip?.toLowerCase().includes(searchLower) ||
        item.protocol?.toLowerCase().includes(searchLower) ||
        (item.anomaly_details && item.anomaly_details.toLowerCase().includes(searchLower))
      );
    });
  }, [filesData, searchTerm, statusFilter]);

  const getStatusColor = (prediction, confidence) => {
    if (prediction === 'Anomaly') {
      return confidence > 0.7 ? 'error' : 'warning';
    }
    return 'success';
  };

  const renderAnomalyChart = () => {
    if (!filesData.length || !filesData[0].stats.anomalyTypes.length) {
      return (
        <Paper elevation={4} className="chart-card">
          <Typography variant="h6" mb={2}>Распределение аномалий</Typography>
          <Typography color="textSecondary" align="center" py={4}>
            Аномалии не обнаружены
          </Typography>
        </Paper>
      );
    }

    return (
      <Paper elevation={4} className="chart-card">
        <Typography variant="h6" mb={2}>Распределение аномалий</Typography>
        <ResponsiveContainer width="100%" height={400}>
          <BarChart
            data={filesData[0].stats.anomalyTypes.sort((a, b) => b.count - a.count)}
            layout="vertical"
            margin={{ top: 20, right: 30, left: 40, bottom: 20 }}
          >
            <XAxis type="number" />
            <YAxis dataKey="type" type="category" width={120} />
            <RechartsTooltip />
            <Legend />
            <Bar dataKey="count" name="Количество" fill="#ff4081" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </Paper>
    );
  };

  const renderProtocolChart = () => (
    <Paper elevation={4} className="chart-card">
      <Typography variant="h6" mb={2}>Распределение протоколов</Typography>
      <ResponsiveContainer width="100%" height={400}>
        <PieChart>
          <Pie
            data={filesData[0]?.stats.protocols || []}
            dataKey="count"
            nameKey="proto"
            cx="50%" cy="50%"
            outerRadius={110}
            label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
          >
            {(filesData[0]?.stats.protocols || []).map((entry, idx) => (
              <Cell key={`cell-${idx}`} fill={`hsl(${idx * 360 / (filesData[0]?.stats.protocols.length || 1)}, 70%, 50%)`} />
            ))}
          </Pie>
          <RechartsTooltip />
        </PieChart>
      </ResponsiveContainer>
    </Paper>
  );

  const renderTimelineChart = () => {
    if (!filesData.length) return null;

    const timeData = filteredData.reduce((acc, item) => {
      if (item.prediction === 'Anomaly') {
        const time = new Date(item.timestamp).toLocaleTimeString([], {
          hour: '2-digit', minute: '2-digit'
        });
        acc[time] = (acc[time] || 0) + 1;
      }
      return acc;
    }, {});

    const chartData = Object.entries(timeData).map(([time, count]) => ({
      time,
      count
    })).sort((a, b) => a.time.localeCompare(b.time));

    return (
      <Paper elevation={4} className="chart-card">
        <Typography variant="h6" mb={2}>Временная шкала аномалий</Typography>
        <ResponsiveContainer width="100%" height={400}>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="time" />
            <YAxis />
            <RechartsTooltip />
            <Line
              type="monotone"
              dataKey="count"
              stroke="#ff4081"
              strokeWidth={2}
              dot={{ r: 4 }}
              activeDot={{ r: 6 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </Paper>
    );
  };

  const renderTrafficTable = () => {
    if (!filesData.length) return null;

    const formatTime = (timestamp) => {
      return new Date(timestamp).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
    };

    return (
      <Paper elevation={4} className="table-card">
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Typography variant="h6">
            Детализация трафика ({filteredData.length} пакетов)
            {filesData[0]?.stats.anomalies > 0 && (
              <Typography component="span" color="error.main" ml={1}>
                ({filesData[0].stats.anomalies} аномалий)
              </Typography>
            )}
          </Typography>
          <Box display="flex" alignItems="center" gap={2}>
            <Box display="flex" alignItems="center" gap={1}>
              <Button
                variant={statusFilter === 'all' ? 'contained' : 'outlined'}
                onClick={() => setStatusFilter('all')}
                size="small"
              >
                Все
              </Button>
              <Button
                variant={statusFilter === 'normal' ? 'contained' : 'outlined'}
                onClick={() => setStatusFilter('normal')}
                color="success"
                size="small"
              >
                Нормальные
              </Button>
              <Button
                variant={statusFilter === 'anomaly' ? 'contained' : 'outlined'}
                onClick={() => setStatusFilter('anomaly')}
                color="error"
                size="small"
              >
                Аномальные
              </Button>
            </Box>
            <Box display="flex" alignItems="center">
              <SearchIcon sx={{ mr: 1, color: 'action.active' }} />
              <TextField
                variant="outlined"
                size="small"
                placeholder="Поиск по IP, протоколу..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                sx={{ width: 300 }}
              />
            </Box>
          </Box>
        </Box>

        <TableContainer sx={{ maxHeight: 600 }}>
          <Table stickyHeader size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ width: '10%' }}>Время</TableCell>
                <TableCell sx={{ width: '20%' }}>Источник</TableCell>
                <TableCell sx={{ width: '20%' }}>Назначение</TableCell>
                <TableCell sx={{ width: '10%' }}>Протокол</TableCell>
                <TableCell sx={{ width: '10%' }} align="right">Размер (байт)</TableCell>
                <TableCell sx={{ width: '10%' }} align="center">Статус</TableCell>
                <TableCell sx={{ width: '10%' }} align="center">Тип аномалии</TableCell>
                <TableCell sx={{ width: '10%' }} align="center">Уверенность</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredData.slice(0, 1000).map((row, idx) => {
                const isAnomaly = row.prediction === 'Anomaly';
                const statusColor = getStatusColor(row.prediction, row.confidence);
                const confidencePercent = Math.min(100, Math.round(row.confidence * 100));
                const anomalyType = row.anomaly_details || (isAnomaly ? 'SYN Flood' : 'Normal');

                return (
                  <TableRow
                    key={idx}
                    hover
                    sx={{
                      bgcolor: isAnomaly
                        ? (row.confidence > 0.7
                            ? 'rgba(255, 0, 0, 0.05)'
                            : 'rgba(255, 165, 0, 0.05)')
                        : undefined,
                      '&:hover': {
                        bgcolor: isAnomaly
                          ? (row.confidence > 0.7
                              ? 'rgba(255, 0, 0, 0.08)'
                              : 'rgba(255, 165, 0, 0.08)')
                          : 'rgba(0, 0, 0, 0.04)'
                      }
                    }}
                  >
                    <TableCell>{formatTime(row.timestamp)}</TableCell>
                    <TableCell sx={{ fontFamily: 'monospace' }}>
                      <Chip
                        label={row.src_ip}
                        size="small"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell sx={{ fontFamily: 'monospace' }}>
                      <Chip
                        label={row.dst_ip}
                        size="small"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={row.protocol}
                        size="small"
                        color={
                          row.protocol.toLowerCase().includes('tcp') ? 'primary' :
                          row.protocol.toLowerCase().includes('udp') ? 'secondary' : 'default'
                        }
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Typography variant="body2">
                        {row.details.bytes.toLocaleString()}
                      </Typography>
                    </TableCell>
                    <TableCell align="center">
                      <Chip
                        label={row.prediction}
                        color={statusColor}
                        size="small"
                        sx={{
                          fontWeight: 'bold',
                          minWidth: 80
                        }}
                      />
                    </TableCell>
                    <TableCell align="center">
                      {isAnomaly ? (
                        <Tooltip title={anomalyType} arrow>
                          <Chip
                            label={anomalyType.length > 10
                              ? `${anomalyType.substring(0, 8)}...`
                              : anomalyType}
                            color="error"
                            size="small"
                            variant="outlined"
                            sx={{ maxWidth: 100 }}
                          />
                        </Tooltip>
                      ) : (
                        <Typography variant="body2" color="textSecondary">-</Typography>
                      )}
                    </TableCell>
                    <TableCell align="center">
                      <Tooltip title={`Уверенность: ${confidencePercent}%`} arrow>
                        <Box display="flex" alignItems="center" gap={1}>
                          <Box width={60} position="relative">
                            <LinearProgress
                              variant="determinate"
                              value={confidencePercent}
                              color={statusColor}
                              sx={{
                                height: 10,
                                borderRadius: 5,
                                backgroundColor: theme.palette[statusColor].light,
                                '& .MuiLinearProgress-bar': {
                                  borderRadius: 5,
                                  backgroundColor: theme.palette[statusColor].main
                                }
                              }}
                            />
                            <Typography
                              variant="caption"
                              sx={{
                                position: 'absolute',
                                top: '50%',
                                left: '50%',
                                transform: 'translate(-50%, -50%)',
                                color: confidencePercent > 50 ? 'white' : 'text.secondary',
                                fontWeight: 'bold',
                                fontSize: '0.7rem'
                              }}
                            >
                              {confidencePercent}%
                            </Typography>
                          </Box>
                        </Box>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>
    );
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Box className="main-wrapper">
        {!filesData.length && !loading && (
          <Box {...getRootProps()} className={`dropzone ${isDragActive ? 'active' : ''}`}>
            <input {...getInputProps()} />
            <SecurityIcon className="shield-icon" />
            <Typography variant="h4" gutterBottom>Анализатор сетевого трафика</Typography>
            <Typography variant="body1" paragraph>Перетащите PCAP-файл сюда или нажмите для выбора</Typography>
            <Button variant="contained" startIcon={<CloudUploadIcon />}>Выбрать файл</Button>
            <Typography variant="caption" mt={2}>Поддерживаемые форматы: .pcap, .pcapng</Typography>
          </Box>
        )}

        {filesData.length > 0 && (
          <Container maxWidth="xl" className="container">
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
              <Typography variant="h5">Анализ файла: {selectedFile?.name}</Typography>
              <Button
                variant="contained"
                color="primary"
                onClick={exportToExcel}
                disabled={exportLoading || !filesData.length}
                startIcon={exportLoading ? <CircularProgress size={24} /> : <InsertChartIcon />}
                sx={{
                  minWidth: 180,
                  transition: 'all 0.3s',
                  '&:hover': {
                    transform: 'translateY(-2px)'
                  }
                }}
              >
                {exportLoading ? 'Экспорт...' : 'Экспорт в Excel'}
              </Button>
            </Box>

            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>{renderAnomalyChart()}</Grid>
              <Grid item xs={12} md={4}>{renderProtocolChart()}</Grid>
              <Grid item xs={12} md={4}>{renderTimelineChart()}</Grid>
              <Grid item xs={12}>{renderTrafficTable()}</Grid>
            </Grid>
          </Container>
        )}

        <Dialog open={loading}>
          <DialogTitle>Анализ файла</DialogTitle>
          <DialogContent style={{ textAlign: 'center', padding: '20px' }}>
            <div className="custom-spinner"><div></div><div></div><div></div><div></div></div>
            <Typography variant="body1" mt={2}>Обрабатывается файл: {selectedFile?.name}</Typography>
          </DialogContent>
        </Dialog>
      </Box>
    </ThemeProvider>
  );
};

export default App;