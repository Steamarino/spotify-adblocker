import {
	exists as fsExists,
	writeFile as fsWriteFile,
	readFile as fsReadFile
} from 'node:fs';
import {join as pathJoin} from 'node:path';
import {
	series as asyncSeries,
	parallel as asyncParallel,
	auto as asyncAuto
} from 'async'
import {bind as mkdirpBind} from 'mkdirp'
import {pki, md} from 'node-forge';

const CAattrs: object[] = [{
	name: 'commonName',
	value: 'https://github.com/checkium/spotify-adblock-windows'
}, {
	name: 'countryName',
	value: 'spotify-adblock-windows'
}, {
	shortName: 'ST',
	value: 'spotify-adblock-windows'
}, {
	name: 'localityName',
	value: 'spotify-adblock-windows'
}, {
	name: 'organizationName',
	value: 'spotify-adblock-windows'
}, {
	shortName: 'OU',
	value: 'spotify-adblock-windows'
}];

const CAextensions: object[] = [{
	name: 'basicConstraints',
	cA: true
}, {
	name: 'keyUsage',
	keyCertSign: true,
	digitalSignature: true,
	nonRepudiation: true,
	keyEncipherment: true,
	dataEncipherment: true
}, {
	name: 'extKeyUsage',
	serverAuth: true,
	clientAuth: true,
	codeSigning: true,
	emailProtection: true,
	timeStamping: true
}, {
	name: 'nsCertType',
	client: true,
	server: true,
	email: true,
	objsign: true,
	sslCA: true,
	emailCA: true,
	objCA: true
}, {
	name: 'subjectKeyIdentifier'
}];

const ServerAttrs: object[] = [{
	name: 'countryName',
	value: 'spotify-adblock-windows'
}, {
	shortName: 'ST',
	value: 'spotify-adblock-windows'
}, {
	name: 'localityName',
	value: 'spotify-adblock-windows'
}, {
	name: 'organizationName',
	value: 'spotify-adblock-windows'
}, {
	shortName: 'OU',
	value: 'spotify-adblock-windows'
}];

const ServerExtensions: object[] = [{
	name: 'basicConstraints',
	cA: false
}, {
	name: 'keyUsage',
	keyCertSign: false,
	digitalSignature: true,
	nonRepudiation: false,
	keyEncipherment: true,
	dataEncipherment: true
}, {
	name: 'extKeyUsage',
	serverAuth: true,
	clientAuth: true,
	codeSigning: false,
	emailProtection: false,
	timeStamping: false
}, {
	name: 'nsCertType',
	client: true,
	server: true,
	email: false,
	objsign: false,
	sslCA: false,
	emailCA: false,
	objCA: false
}, {
	name: 'subjectKeyIdentifier'
}];

export class CA {
	private static instance: CA;

	private baseCAFolder: string;
	private certsFolder: string;
	private keysFolder: string;
	private CAkeys: {
		privateKey: any;
		publicKey: any;
	};
	private CAcert: any;

	public static getInstance(): CA {
		if (!this.instance) {
			this.instance = new CA();
		}
		return this.instance;
	}

	public create(caFolder: string, callback: any): any {
		this.baseCAFolder = caFolder;
		this.certsFolder = pathJoin(this.baseCAFolder, 'certs');
		this.keysFolder = pathJoin(this.baseCAFolder, 'keys');
		asyncSeries([
			mkdirpBind(null, this.baseCAFolder),
			mkdirpBind(null, this.certsFolder),
			mkdirpBind(null, this.keysFolder),
			function (callback) {
				fsExists(pathJoin(this.certsFolder, 'ca.crt'), (exists: boolean) => {
					if (exists) {
						this.loadCA(callback);
					} else {
						this.generateCA(callback);
					}
				});
			}
		], function (err) {
			if (err) {
				return callback(err);
			}
			return callback(null, this);
		});
	};

	private randomSerialNumber(): string {
		// generate random 16 bytes hex string
		let sn: string;
		for (let i = 0; i < 4; i++) {
			sn += ('00000000' + Math.floor(Math.random() * Math.pow(256, 4)).toString(16)).slice(-8);
		}
		return sn;
	}

	private generateCA(callback) {
		pki.rsa.generateKeyPair({bits: 2048}, function (err, keys) {
			if (err) {
				return callback(err);
			}
			let cert = pki.createCertificate();
			cert.publicKey = keys.publicKey;
			cert.serialNumber = this.randomSerialNumber();
			cert.validity.notBefore = new Date();
			cert.validity.notBefore.setDate(cert.validity.notBefore.getDate() - 1);
			cert.validity.notAfter = new Date();
			cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
			cert.setSubject(CAattrs);
			cert.setIssuer(CAattrs);
			cert.setExtensions(CAextensions);
			cert.sign(keys.privateKey, md.sha256.create());
			this.CAcert = cert;
			this.CAkeys = keys;
			asyncParallel([
				fsWriteFile.bind(null, pathJoin(this.certsFolder, 'ca.crt'), pki.certificateToPem(cert)),
				fsWriteFile.bind(null, pathJoin(this.keysFolder, 'ca.private.key'), pki.privateKeyToPem(keys.privateKey)),
				fsWriteFile.bind(null, pathJoin(this.keysFolder, 'ca.public.key'), pki.publicKeyToPem(keys.publicKey))
			], callback);
		});
	};

	private loadCA(callback): any {
		asyncAuto({
			certPEM: function (callback) {
				fsReadFile(pathJoin(this.certsFolder, 'ca.crt'), 'utf-8', callback);
			},
			keyPrivatePEM: function (callback) {
				fsReadFile(pathJoin(this.keysFolder, 'ca.private.key'), 'utf-8', callback);
			},
			keyPublicPEM: function (callback) {
				fsReadFile(pathJoin(this.keysFolder, 'ca.public.key'), 'utf-8', callback);
			}
		}, function (err, results) {
			if (err) {
				return callback(err);
			}
			this.CAcert = pki.certificateFromPem(results.certPEM);
			this.CAkeys = {
				privateKey: pki.privateKeyFromPem(results.keyPrivatePEM),
				publicKey: pki.publicKeyFromPem(results.keyPublicPEM)
			};
			return callback();
		});
	};

	public generateServerCertificateKeys(hosts: string | string[], cb: any): void {
		if (typeof (hosts) === "string") {
			hosts = [hosts];
		}
		var mainHost = hosts[0];
		var keysServer = pki.rsa.generateKeyPair(2048);
		var certServer = pki.createCertificate();
		certServer.publicKey = keysServer.publicKey;
		certServer.serialNumber = this.randomSerialNumber();
		certServer.validity.notBefore = new Date();
		certServer.validity.notBefore.setDate(certServer.validity.notBefore.getDate() - 1);
		certServer.validity.notAfter = new Date();
		certServer.validity.notAfter.setFullYear(certServer.validity.notBefore.getFullYear() + 2);
		var attrsServer = ServerAttrs.slice(0);
		attrsServer.unshift({
			name: 'commonName',
			value: mainHost
		})
		certServer.setSubject(attrsServer);
		certServer.setIssuer(this.CAcert.issuer.attributes);
		certServer.setExtensions(ServerExtensions.concat([{
			name: 'subjectAltName',
			altNames: hosts.map(function (host) {
				if (host.match(/^[\d\.]+$/)) {
					return {type: 7, ip: host};
				}
				return {type: 2, value: host};
			})
		}]));
		certServer.sign(this.CAkeys.privateKey, md.sha256.create());
		var certPem = pki.certificateToPem(certServer);
		var keyPrivatePem = pki.privateKeyToPem(keysServer.privateKey)
		var keyPublicPem = pki.publicKeyToPem(keysServer.publicKey)
		fsWriteFile(this.certsFolder + '/' + mainHost.replace(/\*/g, '_') + '.crt', certPem, (error) => {
			if (error) {
				console.error("Failed to save certificate to disk in " + this.certsFolder, error);
			}
		});
		fsWriteFile(this.keysFolder + '/' + mainHost.replace(/\*/g, '_') + '.key', keyPrivatePem, (error) => {
			if (error) {
				console.error("Failed to save private key to disk in " + this.keysFolder, error);
			}
		});
		fsWriteFile(this.keysFolder + '/' + mainHost.replace(/\*/g, '_') + '.public.key', keyPublicPem, (error) => {
			if (error) {
				console.error("Failed to save public key to disk in " + this.keysFolder, error);
			}
		});
		// returns synchronously even before files get written to disk
		cb(certPem, keyPrivatePem);
	};

	private getCACertPath(): string {
		return this.certsFolder + '/ca.crt';
	};
}