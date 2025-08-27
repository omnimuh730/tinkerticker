import React from 'react';

function TrafficDisplay({ trafficData }) {
  // For now, just display the raw data
  // You'll want to format this data for better display later

  if (error) {
    return <div>Error fetching traffic data: {error.toString()}</div>;
  }

  return (
    <div>
      <h2>Network Traffic Data</h2>
      <pre>{JSON.stringify(trafficData, null, 2)}</pre>
    </div>
  );
}

export default TrafficDisplay;
