const { execSync } = require('child_process')
const fs = require('fs')

let paths = [
  "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\MSBuild\\Current\\Bin\\MSBuild.exe",
  "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\MSBuild\\Current\\Bin\\MSBuild.exe", 
  "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\MSBuild\\Current\\Bin\\MSBuild.exe", 
  "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\MSBuild\\Current\\Bin\\MSBuild.exe", 
]

let path
for(let i = 0; i < paths.length; i++) {
  if(fs.existsSync(paths[i])) {
    path = paths[i]
    break
  }
}

if(!path) {
  console.error('MSBuild not found. To install, type \'yarn install-tools\'.')
  process.exit(1)
}

console.log(`Using MSBuild located at ${path}`)

execSync(`"${path}" /p:Configuration=Release${process.argv.length > 2 && process.argv[2] === 'tls' ? '-TLS' : ''} /p:Platform=x64 /t:Rebuild /clp:NoSummary;NoItemAndPropertyList;Verbosity=minimal bclib++.sln`, {
  cwd: __dirname,
  stdio: 'inherit'
})