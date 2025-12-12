const WebSocket = require('ws');

const cmd = process.argv[2] || 'id';
const ws = new WebSocket('ws://127.0.0.1:1233/ws', ['webtty']);

ws.on('open', function() {
    ws.send(JSON.stringify({Arguments: '', AuthToken: ''}));
});

ws.on('message', function(data) {
    const msg = data.toString();
    const type = msg[0];
    const payload = msg.slice(1);
    
    if (type === '1') {
        process.stdout.write(Buffer.from(payload, 'base64').toString());
    }
});

setTimeout(() => {
    ws.send('1' + cmd + '\n');
}, 300);

setTimeout(() => {
    ws.close();
    process.exit(0);
}, 1500);
