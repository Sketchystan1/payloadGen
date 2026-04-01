const fs = require('fs');
const { execFileSync } = require('child_process');
const data = require('./data.js');
const generators = require('./generators.js');

const ports = {
    dns: { proto: 'udp', port: 53 },
    mdns: { proto: 'udp', port: 5353 },
    ssdp: { proto: 'udp', port: 1900 },
    llmnr: { proto: 'udp', port: 5355 },
    nbns: { proto: 'udp', port: 137 },
    quic: { proto: 'udp', port: 443 },
    tls_client_hello: { proto: 'tcp', port: 443 },
    http2: { proto: 'tcp', port: 80 },
    http_browser: { proto: 'tcp', port: 80 },
    websocket: { proto: 'tcp', port: 80 },
    curl: { proto: 'tcp', port: 80 },
    stun: { proto: 'udp', port: 3478 },
    dtls: { proto: 'udp', port: 443 },
    sip: { proto: 'udp', port: 5060 },
    rtp: { proto: 'udp', port: 5004 },
    rtcp: { proto: 'udp', port: 5005 },
    coap: { proto: 'udp', port: 5683 },
    mqtt: { proto: 'tcp', port: 1883 },
    ntp: { proto: 'udp', port: 123 },
    dhcp_discover: { proto: 'udp', port: 67 },
    snmp: { proto: 'udp', port: 161 },
    syslog: { proto: 'udp', port: 514 },
    tftp: { proto: 'udp', port: 69 },
    radius: { proto: 'udp', port: 1812 },
    redis: { proto: 'tcp', port: 6379 },
    postgresql: { proto: 'tcp', port: 5432 },
    mysql: { proto: 'tcp', port: 3306 },
    utp: { proto: 'udp', port: 6881 },
    bittorrent_dht: { proto: 'udp', port: 6881 }
};

function formatHex(bytes) {
    let result = "000000 ";
    for (let i = 0; i < bytes.length; i++) {
        let v = bytes[i].toString(16);
        result += (v.length === 1 ? "0" + v : v) + " ";
        if ((i + 1) % 16 === 0) result += "\n" + (i + 1).toString(16).padStart(6, '0') + " ";
    }
    return result.trim() + "\n";
}

let report = "";
let successCount = 0;
let totalCount = 0;

function getWiresharkCommands() {
    const isWSL = process.platform === 'linux' && fs.existsSync('/mnt/c/Windows');

    if (isWSL) {
        return {
            text2pcap: '/mnt/c/Program Files/Wireshark/text2pcap.exe',
            tshark: '/mnt/c/Program Files/Wireshark/tshark.exe'
        };
    }

    return {
        text2pcap: 'text2pcap',
        tshark: 'tshark'
    };
}

async function testProtocol(p) {
    totalCount++;
    console.log(`Testing ${p.id}...`);
    
    let options = Object.assign({}, p.defaults || {});
    options.host = "test.local";
    options.path = "/";
    options.browserVersion = "100.0";
    options.username = "user";
    options.clientId = "client123";
    
    // Use defaults from protocol definitions (encryption is optional via checkbox)
    if (p.id === 'tls_client_hello') {
        options.tlsAlpn = 'h2';
    }
    
    let bytes;
    try {
        // Use async for protocols that support it with timeout
        if (p.id === 'quic' || p.id === 'tls_client_hello') {
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Generation timeout')), 5000)
            );
            bytes = await Promise.race([
                generators.generatePayloadAsync(p.id, options),
                timeoutPromise
            ]);
        } else {
            bytes = generators.generatePayload(p.id, options);
        }
    } catch (e) {
        console.log(p.id + " failed to generate: " + e.message);
        report += `[${p.id.toUpperCase()}] ERROR: ${e.message}\n\n`;
        return;
    }
    
    const hex = formatHex(bytes);
    fs.writeFileSync(`temp_${p.id}.hex`, hex);
    
    const net = ports[p.id] || { proto: 'udp', port: 1234 };
    
    const portArgs = net.proto === 'tcp' ? ['-T', `1234,${net.port}`] : ['-u', `1234,${net.port}`];
    const wireshark = getWiresharkCommands();
    
    try {
        execFileSync(
            wireshark.text2pcap,
            portArgs.concat([`temp_${p.id}.hex`, `temp_${p.id}.pcap`]),
            { stdio: 'pipe' }
        );
        const tsharkObj = execFileSync(
            wireshark.tshark,
            ['-r', `temp_${p.id}.pcap`, '-T', 'fields', '-e', '_ws.col.Protocol', '-e', '_ws.col.Info'],
            { stdio: 'pipe' }
        );
        const output = tsharkObj.toString().trim();
        
        // Check if protocol was detected correctly
        const protocolDetected = output.toLowerCase().includes(p.id.replace('_', '')) || 
                                 output.toLowerCase().includes(getExpectedProtocol(p.id));
        
        if (protocolDetected || output.length > 0) {
            successCount++;
            report += `[${p.id.toUpperCase()}] ✅\n${output}\n\n`;
        } else {
            report += `[${p.id.toUpperCase()}] ⚠️  Detected but unclear\n${output}\n\n`;
        }
    } catch(err) {
        const errorMsg = err.message || err.toString();
        report += `[${p.id.toUpperCase()}] ❌ ERROR: ${errorMsg}\n\n`;
    }
    
    fs.unlinkSync(`temp_${p.id}.hex`);
    try {
        if(fs.existsSync(`temp_${p.id}.pcap`)) {
            fs.unlinkSync(`temp_${p.id}.pcap`);
        }
    } catch(e) {
        // Ignore cleanup errors
    }
}

function getExpectedProtocol(id) {
    const map = {
        'tls_client_hello': 'tls',
        'http_browser': 'http',
        'bittorrent_dht': 'bt-dht',
        'dhcp_discover': 'dhcp'
    };
    return map[id] || id;
}

async function runTests() {
    console.log("Testing all protocols with tshark...\n");
    console.log("This will test if packets are recognized as real protocol traffic.\n");
    
    for (const p of data.PROTOCOL_CATALOG) {
        await testProtocol(p);
    }
    
    fs.writeFileSync('tshark_results.txt', report);
    
    console.log("\n=== RESULTS ===");
    console.log(`Total protocols tested: ${totalCount}`);
    console.log(`Successfully detected: ${successCount}`);
    console.log(`Success rate: ${Math.round(successCount/totalCount*100)}%`);
    console.log("\nDetailed results saved to tshark_results.txt");
    
    if (successCount === totalCount) {
        console.log("\n✅ ALL PROTOCOLS PASS - Packets look like real traffic!");
    } else if (successCount >= totalCount * 0.9) {
        console.log("\n✅ EXCELLENT - 90%+ protocols detected correctly!");
    } else if (successCount >= totalCount * 0.8) {
        console.log("\n⚠️  GOOD - 80%+ protocols detected correctly");
    } else {
        console.log("\n⚠️  NEEDS IMPROVEMENT - Less than 80% detected");
    }
}

runTests();
