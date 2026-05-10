package server

var indexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>eBPF Security Monitor</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a2e;
            color: #eee;
            min-height: 100vh;
        }
        
        .header {
            background: linear-gradient(135deg, #16213e 0%, #0f3460 100%);
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        }
        
        .header h1 {
            font-size: 28px;
            color: #e94560;
        }
        
        .header .stats {
            display: flex;
            gap: 30px;
            margin-top: 10px;
            font-size: 14px;
            color: #aaa;
        }
        
        .container {
            display: flex;
            height: calc(100vh - 100px);
        }
        
        .sidebar {
            width: 250px;
            background: #16213e;
            padding: 20px;
            overflow-y: auto;
        }
        
        .sidebar h3 {
            color: #e94560;
            margin-bottom: 15px;
            font-size: 16px;
        }
        
        .filter-group {
            margin-bottom: 20px;
        }
        
        .filter-group label {
            display: block;
            margin-bottom: 5px;
            color: #aaa;
            font-size: 13px;
        }
        
        .filter-group input[type="checkbox"] {
            margin-right: 8px;
        }
        
        .filter-group input[type="text"],
        .filter-group select {
            width: 100%;
            padding: 8px;
            background: #1a1a2e;
            border: 1px solid #333;
            color: #eee;
            border-radius: 4px;
            font-size: 13px;
        }
        
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            padding: 20px;
            overflow: hidden;
        }
        
        .tabs {
            display: flex;
            gap: 5px;
            margin-bottom: 15px;
        }
        
        .tab {
            padding: 10px 20px;
            background: #16213e;
            border: none;
            color: #aaa;
            cursor: pointer;
            border-radius: 4px 4px 0 0;
            transition: all 0.3s;
        }
        
        .tab.active {
            background: #0f3460;
            color: #e94560;
        }
        
        .tab:hover {
            background: #0f3460;
        }
        
        .event-table-container {
            flex: 1;
            overflow: hidden;
            background: #16213e;
            border-radius: 0 4px 4px 4px;
        }
        
        .event-table {
            width: 100%;
            height: 100%;
            border-collapse: collapse;
            display: block;
            overflow-y: auto;
        }
        
        .event-table thead {
            position: sticky;
            top: 0;
            background: #0f3460;
            z-index: 10;
        }
        
        .event-table th,
        .event-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #333;
            font-size: 13px;
        }
        
        .event-table th {
            color: #e94560;
            font-weight: 600;
        }
        
        .event-row {
            transition: background 0.2s;
        }
        
        .event-row:hover {
            background: #1f2b47;
        }
        
        .event-type {
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
        }
        
        .type-process { background: #4a5568; color: #fff; }
        .type-network { background: #3182ce; color: #fff; }
        .type-file { background: #38a169; color: #fff; }
        
        .event-fork { background: #718096; }
        .event-exec { background: #805ad5; }
        .event-exit { background: #e53e3e; }
        .event-privilege { background: #d69e2e; color: #000; }
        .event-connect { background: #3182ce; }
        .event-accept { background: #00b5d8; }
        .event-close { background: #718096; }
        .event-create { background: #38a169; }
        .event-modify { background: #dd6b20; }
        .event-delete { background: #e53e3e; }
        .event-rename { background: #805ad5; }
        
        .container-badge {
            background: #e94560;
            color: #fff;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            margin-left: 5px;
        }
        
        .connection-status {
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 10px 20px;
            border-radius: 4px;
            font-size: 13px;
        }
        
        .connected {
            background: #38a169;
            color: #fff;
        }
        
        .disconnected {
            background: #e53e3e;
            color: #fff;
        }
        
        .paused {
            background: #d69e2e;
            color: #000;
        }
        
        .controls {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: #e94560;
            color: #fff;
        }
        
        .btn-primary:hover {
            background: #c73e54;
        }
        
        .btn-secondary {
            background: #16213e;
            color: #eee;
        }
        
        .btn-secondary:hover {
            background: #1f2b47;
        }
        
        .stats-card {
            display: inline-block;
            background: #1a1a2e;
            padding: 15px 25px;
            border-radius: 8px;
            margin-right: 15px;
            margin-top: 10px;
        }
        
        .stats-card .number {
            font-size: 32px;
            font-weight: bold;
            color: #e94560;
        }
        
        .stats-card .label {
            font-size: 12px;
            color: #aaa;
            text-transform: uppercase;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ eBPF Security Monitor</h1>
        <div class="stats">
            <div class="stats-card">
                <div class="number" id="processCount">0</div>
                <div class="label">Process Events</div>
            </div>
            <div class="stats-card">
                <div class="number" id="networkCount">0</div>
                <div class="label">Network Events</div>
            </div>
            <div class="stats-card">
                <div class="number" id="fileCount">0</div>
                <div class="label">File Events</div>
            </div>
            <div class="stats-card">
                <div class="number" id="totalCount">0</div>
                <div class="label">Total Events</div>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="sidebar">
            <h3>Filters</h3>
            
            <div class="filter-group">
                <label>Event Types</label>
                <div>
                    <input type="checkbox" id="filterProcess" checked> Process
                </div>
                <div>
                    <input type="checkbox" id="filterNetwork" checked> Network
                </div>
                <div>
                    <input type="checkbox" id="filterFile" checked> File
                </div>
            </div>
            
            <div class="filter-group">
                <label>Search Process Name</label>
                <input type="text" id="searchProcess" placeholder="e.g., nginx">
            </div>
            
            <div class="filter-group">
                <label>Filter by PID</label>
                <input type="text" id="filterPid" placeholder="e.g., 1234">
            </div>
            
            <div class="filter-group">
                <label>Container Filter</label>
                <select id="containerFilter">
                    <option value="all">All</option>
                    <option value="host">Host Only</option>
                    <option value="container">Container Only</option>
                </select>
            </div>
            
            <div class="filter-group">
                <label>Max Events</label>
                <select id="maxEvents">
                    <option value="100">100</option>
                    <option value="500" selected>500</option>
                    <option value="1000">1000</option>
                    <option value="5000">5000</option>
                </select>
            </div>
        </div>
        
        <div class="main-content">
            <div class="controls">
                <button class="btn btn-primary" id="pauseBtn">⏸️ Pause</button>
                <button class="btn btn-secondary" id="clearBtn">🗑️ Clear</button>
                <button class="btn btn-secondary" id="exportBtn">📥 Export JSON</button>
            </div>
            
            <div class="tabs">
                <button class="tab active" data-tab="all">All Events</button>
                <button class="tab" data-tab="process">Process</button>
                <button class="tab" data-tab="network">Network</button>
                <button class="tab" data-tab="file">File</button>
            </div>
            
            <div class="event-table-container">
                <table class="event-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Type</th>
                            <th>PID</th>
                            <th>Process</th>
                            <th>User</th>
                            <th>Details</th>
                            <th>Container</th>
                        </tr>
                    </thead>
                    <tbody id="eventBody">
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <div class="connection-status connected" id="connectionStatus">
        ● Connected
    </div>
    
    <script>
        let ws = null;
        let events = [];
        let paused = false;
        let stats = { process: 0, network: 0, file: 0, total: 0 };
        
        function connect() {
            const wsUrl = 'ws://' + window.location.host + '/ws';
            ws = new WebSocket(wsUrl);
            
            ws.onopen = () => {
                document.getElementById('connectionStatus').className = 'connection-status connected';
                document.getElementById('connectionStatus').textContent = '● Connected';
            };
            
            ws.onclose = () => {
                document.getElementById('connectionStatus').className = 'connection-status disconnected';
                document.getElementById('connectionStatus').textContent = '● Disconnected';
                setTimeout(connect, 3000);
            };
            
            ws.onerror = (err) => {
                console.error('WebSocket error:', err);
            };
            
            ws.onmessage = (event) => {
                if (!paused) {
                    const data = JSON.parse(event.data);
                    addEvent(data);
                }
            };
        }
        
        function addEvent(event) {
            events.unshift(event);
            
            const maxEvents = parseInt(document.getElementById('maxEvents').value);
            if (events.length > maxEvents) {
                events = events.slice(0, maxEvents);
            }
            
            stats[event.type]++;
            stats.total++;
            updateStats();
            renderEvents();
        }
        
        function updateStats() {
            document.getElementById('processCount').textContent = stats.process;
            document.getElementById('networkCount').textContent = stats.network;
            document.getElementById('fileCount').textContent = stats.file;
            document.getElementById('totalCount').textContent = stats.total;
        }
        
        function renderEvents() {
            const tbody = document.getElementById('eventBody');
            const processFilter = document.getElementById('filterProcess').checked;
            const networkFilter = document.getElementById('filterNetwork').checked;
            const fileFilter = document.getElementById('filterFile').checked;
            const searchTerm = document.getElementById('searchProcess').value.toLowerCase();
            const pidFilter = document.getElementById('filterPid').value;
            const containerFilter = document.getElementById('containerFilter').value;
            const activeTab = document.querySelector('.tab.active').dataset.tab;
            
            const filtered = events.filter(e => {
                if (activeTab !== 'all' && e.type !== activeTab) return false;
                if (!processFilter && e.type === 'process') return false;
                if (!networkFilter && e.type === 'network') return false;
                if (!fileFilter && e.type === 'file') return false;
                if (searchTerm && !e.comm.toLowerCase().includes(searchTerm)) return false;
                if (pidFilter && e.pid.toString() !== pidFilter) return false;
                if (containerFilter === 'host' && e.container_id) return false;
                if (containerFilter === 'container' && !e.container_id) return false;
                return true;
            });
            
            tbody.innerHTML = filtered.slice(0, 500).map(e => createEventRow(e)).join('');
        }
        
        function createEventRow(event) {
            const typeClass = 'type-' + event.type;
            const eventClass = 'event-' + (event.event_type || '');
            const containerBadge = event.container_id ? 
                '<span class="container-badge">' + event.container_id + '</span>' : '';
            
            let details = '';
            if (event.type === 'process') {
                if (event.event_type === 'exec') {
                    details = 'Args: ' + escapeHtml(event.args || '');
                } else if (event.event_type === 'exit') {
                    details = 'Exit Code: ' + event.exit_code;
                } else if (event.event_type === 'privilege') {
                    details = 'Capabilities: ' + event.capabilities;
                } else {
                    details = 'PPID: ' + event.ppid;
                }
            } else if (event.type === 'network') {
                const proto = event.protocol === 6 ? 'TCP' : 'UDP';
                details = proto + ' ' + (event.src_ip || '') + ':' + event.sport + 
                         ' → ' + (event.dst_ip || '') + ':' + event.dport;
            } else if (event.type === 'file') {
                details = escapeHtml(event.path || '');
                if (event.new_path) {
                    details += ' → ' + escapeHtml(event.new_path);
                }
            }
            
            return '<tr class="event-row">' +
                '<td>' + formatTime(event.timestamp) + '</td>' +
                '<td><span class="event-type ' + typeClass + ' ' + eventClass + '">' + 
                    (event.event_type || event.type) + '</span></td>' +
                '<td>' + event.pid + '</td>' +
                '<td>' + escapeHtml(event.comm || '') + containerBadge + '</td>' +
                '<td>' + event.uid + ':' + event.gid + '</td>' +
                '<td>' + details + '</td>' +
                '<td>' + (event.container_id || '-') + '</td>' +
                '</tr>';
        }
        
        function formatTime(timestamp) {
            const date = new Date(timestamp / 1000000);
            return date.toLocaleTimeString() + '.' + 
                   String(date.getMilliseconds()).padStart(3, '0');
        }
        
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        document.getElementById('pauseBtn').addEventListener('click', () => {
            paused = !paused;
            const btn = document.getElementById('pauseBtn');
            if (paused) {
                btn.textContent = '▶️ Resume';
                btn.className = 'btn btn-secondary';
            } else {
                btn.textContent = '⏸️ Pause';
                btn.className = 'btn btn-primary';
            }
        });
        
        document.getElementById('clearBtn').addEventListener('click', () => {
            events = [];
            stats = { process: 0, network: 0, file: 0, total: 0 };
            updateStats();
            renderEvents();
        });
        
        document.getElementById('exportBtn').addEventListener('click', () => {
            const blob = new Blob([JSON.stringify(events, null, 2)], 
                { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'ebpf-events-' + new Date().toISOString() + '.json';
            a.click();
            URL.revokeObjectURL(url);
        });
        
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                renderEvents();
            });
        });
        
        ['filterProcess', 'filterNetwork', 'filterFile', 'searchProcess', 
         'filterPid', 'containerFilter', 'maxEvents'].forEach(id => {
            document.getElementById(id).addEventListener('change', renderEvents);
            document.getElementById(id).addEventListener('input', renderEvents);
        });
        
        connect();
    </script>
</body>
</html>`