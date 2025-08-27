import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api';

function InterfaceSelector({ onSelectInterface }) {
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [error, setError] = useState(null);

  useEffect(() => {
    async function fetchInterfaces() {
      try {
        const result = await invoke('list_interfaces');
        setInterfaces(result);
        if (result.length > 0) {
          setSelectedInterface(result[0]);
          onSelectInterface(result[0]);
        }
      } catch (err) {
        setError(err);
        console.error('Error listing interfaces:', err);
      }
    }
    fetchInterfaces();
  }, [onSelectInterface]);

  const handleSelectChange = (event) => {
    setSelectedInterface(event.target.value);
    onSelectInterface(event.target.value);
  };

  if (error) {
    return <div>Error loading interfaces: {error.toString()}</div>;
  }

  return (
    <div>
      <h2>Select Network Interface</h2>
      <select value={selectedInterface} onChange={handleSelectChange}>
        {interfaces.map((iface) => (
          <option key={iface} value={iface}>
            {iface}
          </option>
        ))}
      </select>
    </div>
  );
}

export default InterfaceSelector;
