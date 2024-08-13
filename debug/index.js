const dgram = require('dgram');
const fs = require('fs');

// DNS server address and port (e.g., Google DNS)
let dnsServer = '8.8.8.8';
dnsServer = '162.159.38.13';
dnsServer = '127.0.0.1';
const dnsPort = 53;

// Domain to query
let domain = 'google.com';
domain = 'dipak.name.np';
domain = 'example.com';

// Output file to log the raw response bytes
let outputFile = 'dipak.HTTPS-ALL.log';
outputFile = 'local.HTTPS-ALL.log';

// Create a UDP socket
const socket = dgram.createSocket('udp4');

// Function to build a DNS query packet
function buildDnsQuery(domain) {
    const queryId = Buffer.from([0x12, 0x34]); // Random query ID
    const flags = Buffer.from([0x01, 0x00]); // Standard query
    const qdCount = Buffer.from([0x00, 0x01]); // One question
    const anCount = Buffer.from([0x00, 0x00]); // No answers
    const nsCount = Buffer.from([0x00, 0x00]); // No authority records
    const arCount = Buffer.from([0x00, 0x00]); // No additional records

    // Convert the domain into DNS query format
    const labels = domain.split('.');
    const qNameParts = labels.map(label => {
        const length = Buffer.from([label.length]);
        const labelBuffer = Buffer.from(label);
        return Buffer.concat([length, labelBuffer]);
    });
    const qName = Buffer.concat([...qNameParts, Buffer.from([0x00])]);

    // const qType = Buffer.from([0x00, what ]); // Type A query
    // const qType = Buffer.from([0x00, 0x01]); // Type A query
    const qType = Buffer.from([0x00, 0x41]); // Type HTTPS query
    const qClass = Buffer.from([0x00, 0x01]); // Class IN

    // Build the complete DNS query packet
    return Buffer.concat([queryId, flags, qdCount, anCount, nsCount, arCount, qName, qType, qClass]);
}

// Handle the response from the DNS server
socket.on('message', (msg) => {
    // Log the raw bytes received from the DNS server
    // fs.appendFileSync(outputFile, `${new Date().toISOString()}: ${msg.toString('hex')}\n`);
    fs.writeFileSync(outputFile, msg);
    console.log(`Logged DNS response to ${outputFile}`);
    socket.close();
});

// Send DNS query
const query = buildDnsQuery(domain);
socket.send(query, dnsPort, dnsServer, (err) => {
    if (err) {
        console.error(`Failed to send DNS query: ${err}`);
        socket.close();
    } else {
        console.log(`DNS query sent to ${dnsServer}`);
    }
});