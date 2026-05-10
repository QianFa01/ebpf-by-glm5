class EventMonitor {
    constructor() {
        this.ws = null;
        this.events = [];
        this.maxEvents = 1000;
        this.currentFilter = 'all';
        this.eventCounts = {
            process: 0,
            network: 0,
            file: 0
        };
        this.reconnectInterval = 5000;
        this.init();
    }

    init() {
        this.setupFilters();
        this.connect();
        this.startStatsPolling();
    }

    setupFilters() {
        const buttons = document.querySelectorAll('.filter-btn');
        buttons.forEach(btn => {
            btn.addEventListener('click', () => {
                buttons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.currentFilter = btn.dataset.filter;
                this.renderEvents();
            });
        });
    }

    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.updateConnectionStatus(true);
        };

        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleEvent(data);
            } catch (e) {
                console.error('Failed to parse event:', e);
            }
        };

        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            this.updateConnectionStatus(false);
            setTimeout(() => this.connect(), this.reconnectInterval);
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.updateConnectionStatus(false);
        };
    }

    updateConnectionStatus(connected) {
        const status = document.getElementById('connection-status');
        const text = status.querySelector('.text');
        
        if (connected) {
            status.classList.remove('disconnected');
            status.classList.add('connected');
            text.textContent = '已连接';
        } else {
            status.classList.remove('connected');
            status.classList.add('disconnected');
            text.textContent = '未连接';
        }
    }

    handleEvent(event) {
        this.events.unshift(event);
        if (this.events.length > this.maxEvents) {
            this.events.pop();
        }

        if (event.type) {
            this.eventCounts[event.type] = (this.eventCounts[event.type] || 0) + 1;
            this.updateEventCounts();
        }

        this.renderEvents();
    }

    formatTimestamp(timestamp) {
        const date = new Date(timestamp / 1000000);
        return date.toLocaleString('zh-CN', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            fractionalSecondDigits: 3
        });
    }

    formatEventType(type) {
        const names = {
            'fork': '进程创建',
            'exec': '进程执行',
            'exit': '进程退出',
            'privilege': '权限提升',
            'connect': 'TCP连接',
            'accept': 'TCP接受',
            'close': 'TCP关闭',
            'udp_send': 'UDP发送',
            'udp_recv': 'UDP接收',
            'create': '文件创建',
            'modify': '文件修改',
            'delete': '文件删除',
            'rename': '文件重命名',
            'chmod': '权限修改',
            'chown': '所有者修改'
        };
        return names[type] || type;
    }

    formatDetails(event) {
        const type = event.data?.event_type;
        
        switch (type) {
            case 'fork':
                return `父进程: ${event.data?.parent_comm || 'N/A'} (PID: ${event.data?.ppid})`;
            case 'exec':
                return `命令: ${event.data?.args || event.data?.comm}`;
            case 'exit':
                return `退出码: ${event.data?.exit_code}`;
            case 'privilege':
                return `UID: ${event.data?.uid} -> 0, Caps: ${event.data?.capabilities}`;
            case 'connect':
            case 'accept':
            case 'close':
                return `${event.data?.src_ip}:${event.data?.sport} -> ${event.data?.dst_ip}:${event.data?.dport}`;
            case 'udp_send':
            case 'udp_recv':
                return `${event.data?.src_ip}:${event.data?.sport} -> ${event.data?.dst_ip}:${event.data?.dport}`;
            case 'create':
                return `创建: ${event.data?.path}`;
            case 'modify':
                return `修改: ${event.data?.path}`;
            case 'delete':
                return `删除: ${event.data?.path}`;
            case 'rename':
                return `${event.data?.path} -> ${event.data?.new_path}`;
            case 'chmod':
                return `${event.data?.path} 权限: ${event.data?.mode?.toString(8)}`;
            case 'chown':
                return `${event.data?.path} UID: ${event.data?.new_uid}, GID: ${event.data?.new_gid}`;
            default:
                return JSON.stringify(event.data || {}).substring(0, 50);
        }
    }

    renderEvents() {
        const tbody = document.getElementById('event-list');
        const filtered = this.currentFilter === 'all' 
            ? this.events 
            : this.events.filter(e => e.type === this.currentFilter);

        const html = filtered.slice(0, 100).map(event => {
            const eventType = event.data?.event_type || 'unknown';
            const comm = event.data?.comm || 'N/A';
            const pid = event.data?.pid || 'N/A';
            const containerId = event.data?.container_id || '';
            
            return `
                <tr>
                    <td>${this.formatTimestamp(event.timestamp)}</td>
                    <td><span class="event-type ${eventType}">${this.formatEventType(eventType)}</span></td>
                    <td>${comm}</td>
                    <td>${pid}</td>
                    <td class="details" title="${this.formatDetails(event)}">${this.formatDetails(event)}</td>
                    <td>${containerId ? `<span class="container-id">${containerId.substring(0, 12)}</span>` : '-'}</td>
                </tr>
            `;
        }).join('');

        tbody.innerHTML = html;
    }

    updateEventCounts() {
        document.getElementById('process-count').textContent = this.eventCounts.process || 0;
        document.getElementById('network-count').textContent = this.eventCounts.network || 0;
        document.getElementById('file-count').textContent = this.eventCounts.file || 0;
        
        const total = Object.values(this.eventCounts).reduce((a, b) => a + b, 0);
        document.getElementById('total-events').textContent = total;
    }

    startStatsPolling() {
        this.fetchStats();
        setInterval(() => this.fetchStats(), 5000);
    }

    async fetchStats() {
        try {
            const response = await fetch('/api/stats');
            const stats = await response.json();
            
            document.getElementById('client-count').textContent = stats.total_clients;
            document.getElementById('uptime').textContent = this.formatUptime(stats.uptime);
            
            if (stats.event_counts) {
                Object.keys(stats.event_counts).forEach(type => {
                    if (this.eventCounts[type] !== undefined) {
                        this.eventCounts[type] = stats.event_counts[type];
                    }
                });
                this.updateEventCounts();
            }
        } catch (e) {
            console.error('Failed to fetch stats:', e);
        }
    }

    formatUptime(seconds) {
        if (seconds < 60) return `${seconds}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
        if (seconds < 86400) {
            const hours = Math.floor(seconds / 3600);
            const mins = Math.floor((seconds % 3600) / 60);
            return `${hours}h ${mins}m`;
        }
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        return `${days}d ${hours}h`;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new EventMonitor();
});