import {connect, Socket} from 'node:net';
import {IncomingMessage} from 'node:http';
import {resolve} from 'node:path';
import {Proxy} from 'http-mitm-proxy';
import {cyan, green, red} from 'colors/safe';
import {CA} from './ca';
import whitelist from '../lists/whitelist';
import blacklist from '../lists/blacklist';
const proxy: Proxy = new Proxy();
const debugRequests = true;

proxy.use(Proxy.gunzip);

class Adblock {
	private blacklistIncludesHost(host: string): boolean {
		let includes = false;
		blacklist.forEach(url => {
			if (url.split("/")[2].includes(host)) {
				includes = true;
			}
		});
		return includes;
	}

	private blacklistIncludesUrl(url: string): boolean {
		let includes: boolean = false;
		blacklist.forEach((blacklistedUrl: string) => {
			if (this.matchesWithWildcard(url, blacklistedUrl)) {
				includes = true;
			}
		});
		return includes;
	}

	private whitelistIncludesHost(host: string): boolean {
		let includes = false;
		whitelist.forEach((whitelistedHost: string) => {
			if (this.matchesWithWildcard(host, whitelistedHost)) {
				includes = true;
			}
		});
		return includes;
	}

	private matchesWithWildcard(str: string, rule: string): boolean {
		const escapeRegex = (str) => str.replace(/([.*+?^=!:${}()|\[\]\/\\])/g, "\\$1");
		return new RegExp("^" + rule.split("*").map(escapeRegex).join(".*") + "$").test(str);
	}

	private filterSocketConnReset(err: any, socketDescription: string) {
		if (err.errno !== 'ECONNRESET') {
			console.log('Got unexpected error on ' + socketDescription, err);
		}
	}

	private async createCA() {
		const ca = CA.getInstance();
		await ca.create(resolve(process.cwd(), 'certs'), (err, lca) => {
			if (err) {
				console.log(err);
				return callback(err);
			}
			ca = lca;
		});
	}

	private async startProxy() {
		await this.createCA();

		proxy.listen({
			port: 8081
		}, e => {
			console.log(green('Proxy is up and ready to operate, listen without disractions!'));
		});
	}

	private registerProxy(): void {
		const ca = CA.getInstance();
		proxy.onConnect(function (req: IncomingMessage, socket: Socket, head: any, callback: any) {
			const host = req.url.split(":")[0];
			const port = req.url.split(":")[1];

			if (this.blacklistIncludesHost(host)) {
				if (debugRequests) {
					console.log(cyan("Host " + host + " is included in the blacklist, continuing with SSL proxying."));
				}
				return callback();
			} else if (this.whitelistIncludesHost(host)) {
				if (debugRequests) {
					console.log(green('Tunneling ' + req.url + ' (whitelisted)'));
				}
				// @ts-ignore
				const conn = connect({
					port: port,
					host: host,
					allowHalfOpen: true
				}, function () {
					conn.on('finish', () => {
						socket.destroy();
					});
					socket.on('close', () => {
						conn.end();
					});
					socket.write('HTTP/1.1 200 OK\r\n\r\n', 'UTF-8', function () {
						conn.pipe(socket);
						socket.pipe(conn);
					})
				});

				conn.on('error', (err: any): void => {
					this.filterSocketConnReset(err, 'PROXY_TO_SERVER_SOCKET');
				});
				socket.on('error', (err: any): void => {
					this.filterSocketConnReset(err, 'CLIENT_TO_PROXY_SOCKET');
				});
			} else if (debugRequests) {
				console.log(red("Blocked request to " + req.url + " (not whitelisted)"));
			}
		});

		proxy.onError((ctx: any, err: any) => {
			if (err.code === "ERR_SSL_SSLV3_ALERT_CERTIFICATE_UNKNOWN") {
				console.error(red("Certificate Authorithy isn't installed, the adblocker can't continue without a trusted CA, refer to https://github.com/checkium/spotify-adblock-windows/ for instructions."));
				process.exit(1);
			}
			console.error('proxy error:', err);
		});

		proxy.onRequest((ctx: any, callback: any): any => {
			const url = "https://" + ctx.clientToProxyRequest.headers.host + ctx.clientToProxyRequest.url;
			if (this.blacklistIncludesUrl(url)) {
				console.log(red("Blocked request to url " + url + " (Blacklisted)"));
				ctx.proxyToClientResponse.end('');
			} else return callback();
		});

		proxy.onCertificateMissing = (ctx: any, files, callback: any): any => {
			const hosts = files.hosts || [ctx.hostname];
			ca.generateServerCertificateKeys(hosts, function (certPEM, privateKeyPEM) {
				callback(null, {
					certFileData: certPEM,
					keyFileData: privateKeyPEM,
					hosts: hosts
				});
			});
			return this;
		};
	}
}