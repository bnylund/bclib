const https = require('https');
const fs = require('fs');
const { execSync } = require('child_process');

function get(url, path, cb) {
  https.get(url, (res) => {
    // if any other status codes are returned, those needed to be added here
    if(res.statusCode === 301 || res.statusCode === 302) {
      return get(res.headers.location, path, cb)
    }

    let body = []

    res.on("data", (chunk) => {
      body.push(chunk)
    });

    res.on("end", () => {
      fs.writeFileSync(path, Buffer.concat(body))
      cb()
    });
  });
}

console.log('Downloading VS BuildTools Installer...')
get("https://aka.ms/vs/17/release/vs_BuildTools.exe", "vs_buildtools.exe", (err) => {
  if(err) {
    console.log('Failed to download buildtools.')
    fs.unlinkSync('vs_buildtools.exe')
    process.exit(1)
  }
  console.log('Done! Installing build tools...')
  execSync(`vs_buildtools.exe --passive --includeRecommended --includeOptional --nocache --wait --add Microsoft.VisualStudio.Workload.VCTools`, {
    stdio: 'inherit',
    cwd: __dirname,
  })
  console.log('Build Tools installed!')
  fs.unlinkSync('vs_buildtools.exe')
})