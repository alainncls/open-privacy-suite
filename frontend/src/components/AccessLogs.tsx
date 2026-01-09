import { useEffect, useState } from 'react';
import { logsApi, AccessLog } from '../api/client';

function AccessLogs() {
  const [logs, setLogs] = useState<AccessLog[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadLogs();
    const interval = setInterval(loadLogs, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const loadLogs = async () => {
    try {
      const response = await logsApi.list(100);
      setLogs(response.data || []);
    } catch (error: any) {
      console.error('Failed to load logs:', error);
      if (error.response) {
        console.error('Response error:', error.response.status, error.response.data);
      }
      setLogs([]); // Set empty array on error
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (statusCode: number) => {
    if (statusCode >= 200 && statusCode < 300) return 'green';
    if (statusCode >= 400 && statusCode < 500) return 'orange';
    return 'red';
  };

  if (loading && logs.length === 0) {
    return <div>Loading access logs...</div>;
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2>Access Logs</h2>
        <button onClick={loadLogs}>Refresh</button>
      </div>

      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '2px solid #ccc' }}>
            <th style={{ padding: '0.5rem', textAlign: 'left' }}>Time</th>
            <th style={{ padding: '0.5rem', textAlign: 'left' }}>External ID</th>
            <th style={{ padding: '0.5rem', textAlign: 'left' }}>Method</th>
            <th style={{ padding: '0.5rem', textAlign: 'left' }}>Status</th>
            <th style={{ padding: '0.5rem', textAlign: 'left' }}>IP Address</th>
          </tr>
        </thead>
        <tbody>
          {logs && logs.length > 0 ? logs.map((log) => (
            <tr key={log.id} style={{ borderBottom: '1px solid #eee' }}>
              <td style={{ padding: '0.5rem' }}>
                {new Date(log.created_at).toLocaleString()}
              </td>
              <td style={{ padding: '0.5rem' }}>{log.external_id}</td>
              <td style={{ padding: '0.5rem' }}>{log.method}</td>
              <td style={{ padding: '0.5rem' }}>
                <span style={{ color: getStatusColor(log.status_code) }}>
                  {log.status_code}
                </span>
              </td>
              <td style={{ padding: '0.5rem' }}>{log.ip_address || '-'}</td>
            </tr>
          )) : (
            <tr>
              <td colSpan={5} style={{ padding: '2rem', textAlign: 'center', color: '#666' }}>
                No access logs yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>

    </div>
  );
}

export default AccessLogs;
