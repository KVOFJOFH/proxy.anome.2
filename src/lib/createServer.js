import getHandler from "./getHandler.js";
import httpProxy from "http-proxy";
import http from "node:http";

export default function createServer(options) {
  options = options || {};

  const httpProxyOptions = {
    xfwd: true,
    secure: process.env.NODE_TLS_REJECT_UNAUTHORIZED !== "0",
  };

  if (options.httpProxyOptions) {
    Object.keys(options.httpProxyOptions).forEach(function (option) {
      httpProxyOptions[option] = options.httpProxyOptions[option];
    });
  }

  const proxyServer = httpProxy.createProxyServer(httpProxyOptions);
  const requestHandler = getHandler(options, proxyServer);
  let server;

  const handleCors = (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET, POST, PUT, DELETE, OPTIONS"
    );
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization"
    );
    res.setHeader("Access-Control-Allow-Credentials", "true");
  
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return true;
    }
    return false;
  };

  const isOriginAllowed = (origin, options) => {
    if (options.originWhitelist.includes("*")) {
      return true;
    }
    if (
      options.originWhitelist.length &&
      !options.originWhitelist.includes(origin)
    ) {
      return false;
    }
    if (
      options.originBlacklist.length &&
      options.originBlacklist.includes(origin)
    ) {
      return false;
    }
    return true;
  };

  if (options.httpsOptions) {
    server = https.createServer(options.httpsOptions, (req, res) => {
      const origin = req.headers.origin || "";
      if (!isOriginAllowed(origin, options)) {
        res.writeHead(403, "Forbidden");
        res.end(
          `The origin "${origin}" was blacklisted by the operator of this proxy.`
        );
        return;
      }
      if (handleCors(req, res)) return;
      requestHandler(req, res);
    });
  } else {
    server = http.createServer((req, res) => {
  const clientIP = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  const ALLOWED_UPTIME_IPS = [
    "69.162.124.224", "69.162.124.225", "74.86.158.106", "69.162.124.226", "3.12.251.153", "3.20.63.178", "3.77.67.4", "3.79.134.69", "3.105.133.239", "3.105.190.221", "3.133.226.214", "3.149.57.90",
"3.212.128.62",
"5.161.61.238",
"5.161.73.160",
"5.161.75.7",
"5.161.113.195",
"5.161.117.52",
"5.161.177.47",
"5.161.194.92",
"5.161.215.244",
"5.223.43.32",
"5.223.53.147",
"5.223.57.22",
"18.116.205.62",
"18.180.208.214",
"18.192.166.72",
"18.193.252.127",
"24.144.78.39",
"24.144.78.185",
"34.198.201.66",
"45.55.123.175",
"45.55.127.146",
"49.13.24.81",
"49.13.130.29",
"49.13.134.145",
"49.13.164.148",
"49.13.167.123",
"52.15.147.27",
"52.22.236.30",
"52.28.162.93",
"52.59.43.236",
"52.87.72.16",
"54.64.67.106",
"54.79.28.129",
"54.87.112.51",
"54.167.223.174",
"54.249.170.27",
"63.178.84.147",
"64.225.81.248",
"64.225.82.147",
"69.162.124.227",
"69.162.124.235",
"69.162.124.238",
"78.46.190.63",
"78.46.215.1",
"78.47.98.55",
"78.47.173.76",
"88.99.80.227",
"91.99.101.207",
"128.140.41.193",
"128.140.106.114",
"129.212.132.140",
"134.199.240.137",
"138.197.53.117",
"138.197.53.138",
"138.197.54.143",
"138.197.54.247",
"138.197.63.92",
"139.59.50.44",
"142.132.180.39",
"143.198.249.237",
"143.198.250.89",
"143.244.196.21",
"143.244.196.211",
"143.244.221.177",
"144.126.251.21",
"146.190.9.187",
"152.42.149.135",
"157.90.155.240",
"157.90.156.63",
"159.69.158.189",
"159.223.243.219",
"161.35.247.201",
"167.99.18.52",
"167.235.143.113",
"168.119.53.160",
"168.119.96.239",
"168.119.123.75",
"170.64.250.64",
"170.64.250.132",
"170.64.250.235",
"178.156.181.172",
"178.156.184.20",
"178.156.185.127",
"178.156.185.231",
"178.156.187.238",
"178.156.189.113",
"178.156.189.249",
"188.166.201.79",
"206.189.241.133",
"209.38.49.1",
"209.38.49.206",
"209.38.49.226",
"209.38.51.43",
"209.38.53.7",
"209.38.124.252",
"216.144.248.18",
"216.144.248.19",
"216.144.248.21",
"216.144.248.22",
"216.144.248.23",
"216.144.248.24",
"216.144.248.25",
"216.144.248.26",
"216.144.248.27",
"216.144.248.28",
"216.144.248.29", "216.144.248.30", "216.245.221.83",
  ];

  if (!ALLOWED_UPTIME_IPS.includes(clientIP)) {
    console.log(`❌ Blocked IP: ${clientIP}`);
    res.writeHead(403, "Forbidden");
    res.end("IP not allowed.");
    return;
  }

  const origin = req.headers.origin || "";

  if (!isOriginAllowed(origin, options)) {
    res.writeHead(403, "Forbidden");
    res.end(`The origin "${origin}" was blacklisted by the operator of this proxy.`);
    return;
  }

  if (handleCors(req, res)) return;

  requestHandler(req, res);
})
  }

  proxyServer.on("error", function (err, req, res) {
    console.error("Proxy error:", err);
    if (res.headersSent) {
      if (!res.writableEnded) {
        res.end();
      }
      return;
    }

    const headerNames = res.getHeaderNames
      ? res.getHeaderNames()
      : Object.keys(res._headers || {});
    headerNames.forEach(function (name) {
      res.removeHeader(name);
    });

    res.writeHead(404, { "Access-Control-Allow-Origin": "*" });
    res.end("Not found because of proxy error: " + err);
  });

  return server;
}
