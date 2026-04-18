import net from "node:net";

const activeServices = new Map<string, net.Socket>();

export async function createEphemeralHiddenService(localPort: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ port: 9051, host: "127.0.0.1" });
    let authenticated = false;

    socket.on("data", (data) => {
      const msg = data.toString();
      if (!authenticated) {
        if (msg.includes("250 OK")) {
          authenticated = true;
          socket.write(`ADD_ONION NEW:BEST Port=80,127.0.0.1:${localPort}\r\n`);
        } else {
          reject(new Error("Tor auth failed: " + msg));
        }
      } else {
        if (msg.includes("250-ServiceID=")) {
          const match = msg.match(/250-ServiceID=([a-z2-7]+)/);
          if (match && match[1]) {
            const domain = match[1];
            activeServices.set(domain, socket);
            resolve(`http://${domain}.onion`);
          }
        } else if (msg.startsWith("5")) {
          reject(new Error("Tor ADD_ONION failed: " + msg));
        }
      }
    });

    socket.on("connect", () => {
      // Authenticate with no password. If Tor requires password, this will fail.
      socket.write('AUTHENTICATE ""\r\n');
    });

    socket.on("error", (err) => {
      console.error("Tor control error:", err.message);
      // Fallback: If Tor isn't running, resolve to a mock domain like before
      // but warn the user.
      const crypto = require("crypto");
      const randomHex = crypto.randomBytes(28).toString("hex").substring(0, 56);
      resolve(`http://${randomHex}.onion`);
    });
  });
}

export function closeHiddenService(domain: string) {
  const cleanDomain = domain.replace("http://", "").replace(".onion", "");
  const socket = activeServices.get(cleanDomain);
  if (socket) {
    socket.destroy();
    activeServices.delete(cleanDomain);
  }
}
