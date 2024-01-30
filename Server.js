const http = require('http');
const fs = require ('fs');
const crypto = require('./RSA');

const server = http.createServer((req, res) => {
    const filePath = req.url === '/' ? '/index.html' : req.url;
    const fullPath = __dirname + filePath;

    fs.readFile(fullPath, (err, data) => {
        if (err) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.write('404 not found');
            res.end();
        } else {
            const contentType = getContentType(filePath);
            res.writeHead(200, { 'Content-Type': contentType });
            res.write(data);
            res.end();
        }
    });
});

function getContentType(filePath) {
    if (filePath.endsWith('.html')) {
        return 'text/html';
    } else if (filePath.endsWith('.js')) {
        return 'text/javascript';
    } else if (filePath.endsWith('.css')) {
        return 'text/css';
    } else {
        return 'text/plain';
    }
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
});
