import axios from "axios";
import chalk from "chalk";

// Check website status
async function checkWebsiteStatus(url) {
  try {
    const response = await axios.get(url, { timeout: 10000 });
    return response;
  } catch (error) {
    console.error(
      chalk.red(`Error: Could not connect to ${url}. Error: ${error.message}`)
    );
    return null;
  }
}

// Common vulnerability patterns for SQLi, XSS, etc..
const patterns = {
  sqlInjection: [
    /union.*select/i,
    /select.*from/i,
    /' OR 1=1 --/i,
    /drop table/i,
    /--/i,
    /\b(select|insert|drop|delete|update|union|--)\b/i,
  ],
  xss: [
    /<script.*?>.*?<\/script>/i,
    /on\w+=/i,
    /javascript:/i,
    /<.*?alert.*?>/i,
  ],
  openRedirect: [/https?:\/\/\S+/i, /redirect/i],
  commandInjection: [/;|\|/i, /&\s*\//i, /sudo/i],
  fileInclusion: [/(\.\.\/|\.\.\\)/i, /%00/i, /\/etc\/passwd/i],
  brokenLinks: /404/i,
  insecureHeaders: [
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
  ],
};

// Generalized vulnerability check function
function checkForVulnerabilities(url, patternType) {
  const matchedPatterns = patterns[patternType];
  return matchedPatterns.some((pattern) => pattern.test(url));
}

// Check for broken links (404)
async function checkForBrokenLinks(url) {
  try {
    const response = await axios.get(url);
    if (response.status === 404) {
      console.log(chalk.red(`Broken link detected: ${url}`));
    }
  } catch (error) {
    console.log(chalk.red(`Broken link detected: ${url}`));
  }
}

// Check for insecure HTTP headers
async function checkInsecureHeaders(url) {
  try {
    const response = await axios.get(url);
    const headers = response.headers;

    patterns.insecureHeaders.forEach((header) => {
      if (!headers[header]) {
        console.log(
          chalk.yellow(`Missing security header: ${header} in ${url}`)
        );
      }
    });
  } catch (error) {
    console.error(
      chalk.red(`Error checking headers for ${url}: ${error.message}`)
    );
  }
}

// Full scan of a website
async function scanWebsite(url) {
  console.log(chalk.blue(`Scanning: ${url}`));

  const response = await checkWebsiteStatus(url);
  if (response) {
    const statusCode = response.status;
    if (statusCode === 200) {
      console.log(chalk.green(`${url} is up and running!`));

      // Perform checks for various vulnerabilities
      [
        "sqlInjection",
        "xss",
        "openRedirect",
        "commandInjection",
        "fileInclusion",
      ].forEach((vulnerability) => {
        if (checkForVulnerabilities(url, vulnerability)) {
          console.log(
            chalk.yellow(
              `Potential ${vulnerability
                .replace(/([A-Z])/g, " $1")
                .toLowerCase()} detected in ${url}`
            )
          );
        }
      });

      // Check for broken links
      await checkForBrokenLinks(url);

      // Check for insecure HTTP headers
      await checkInsecureHeaders(url);
    } else {
      console.log(chalk.red(`${url} returned status code: ${statusCode}`));
    }
  }
}

// Get user input (URL from command line)
const targetURL = process.argv[2];
if (!targetURL) {
  console.log(chalk.red("Please provide a URL to scan."));
  console.log(chalk.blue("Example: node scanner.js https://example.com"));
  process.exit(1);
}

scanWebsite(targetURL);
