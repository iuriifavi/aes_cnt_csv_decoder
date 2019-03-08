(function main() {
	const crypto = require('crypto');
	const path = require('path');
	const fs = require('fs');
	const readline = require('readline');
	const args = require('args');
 
	args
	  .option('keyphrase', 'Password that\'s used for encryption')
	  .option('dir', 'Root directory with file decryption')
	  .option('file', 'Decrypt specific file')
	  .option('prefix', 'Prefix for decrypted files', 'decrypted_')
	  .option('separator', 'Separator character', '$')
 
	const flags = args.parse(process.argv)

	const _rst = '\x1b[0m';
	const _rd = '\x1b[31m';
	const _yl = '\x1b[33m';
	const _gr = '\x1b[32m';
	const _mg = '\x1b[36m';

	console.Red = (...args) => console.log(_rd + [...args].join(' ') , _rst);
	console.Yellow = (...args) => console.log(_yl + [...args].join(' '), _rst);
	console.Green = (...args) => console.log(_gr + [...args].join(' '), _rst);
	console.Magenta = (...args) => console.log(_mg + [...args].join(' '), _rst);

	function prefixCheck(file, regexpr) {
		return regexpr === undefined || (regexpr && regexpr.exec(file.name) !== null)
	}

	function recursiveFileProccessor(root, regexpr, func) {
		const dirs = [root];

		if (typeof regexpr === 'string') {
			regexpr = new RegExp(regexpr);
		}

		while(dirs.length > 0) {
			let dir = dirs.shift();
			console.Red('[SEARCHING]',dir);
			fs.readdirSync(dir, {withFileTypes: true}).forEach(file => {
				if (file.isDirectory())
					dirs.push(path.join(dir, file.name));
				else {
					if (prefixCheck(file, regexpr)) {
						console.Magenta('[FOUND]', path.join(dir, file.name));
						func(path.join(dir, file.name));
					}
				}
			})
		}

		console.Red("[SEARCH DONE]");
	}

	function decodeFile(key, filepath) {
		console.Yellow('[Decoding]',filepath);
		if (path.isAbsolute(filepath) === false) {
			filepath = path.resolve(filepath);
		}
		let filename = path.basename(filepath);
		let decodedFilename = path.join(path.dirname(filepath), flags.prefix + filename);

		var lineReader = readline.createInterface({
		  input: fs.createReadStream(filepath),
		  output: fs.createWriteStream(decodedFilename)
		});

		lineReader.on('line', function (line) {
			if (line.indexOf(flags.separator) === -1)
				this.output.write(line + '\n');
			else {
				line = line.split(',').map( seg => decodeRecord(key, seg)).join(',');
				this.output.write(line + '\n');
			}
		});
		console.Green('[Done]', decodedFilename);
	}

	function decodeRecord(key, line) {
		return decode(key, ...line.split('$'));
	}

	function generateSalt() {
		return Uint8Array.from([ 0, 1, 2, 3, 4, 5, 6, 7 ]);
	}
	  
	function generateSecretKey(paramArrayOfByte, paramArrayOfChar) {
		if (paramArrayOfByte === undefined || paramArrayOfChar === undefined) return;
		return crypto.pbkdf2Sync(paramArrayOfChar, paramArrayOfByte, 10000, 16, 'sha1').toString('base64');
	}

	function getSecreetKey(str) {
		return generateSecretKey(generateSalt(), str);
	}

	function decode(key, iv, data) {
		iv = Buffer.from(iv, 'base64');
		let decipher = crypto.createDecipheriv('aes-128-ctr', key, iv);

		var decryptedText = decipher.update(data, 'base64', 'utf8');
		decryptedText += decipher.final('utf8');

		return decryptedText;
	}


	//Main Decoder
	if (flags.keyphrase === undefined) {
		console.log('You need to set keyphrase using -k option')
		return;
	}

	if (flags.dir === undefined && flags.file === undefined) {
		console.log('File or Directory not set... use -f or -d to set it')
		return;
	}

	let key = getSecreetKey(flags.keyphrase); //arg 1 password
		key = Buffer.from(key, 'base64');

	let regexpr = new RegExp('^(?!' + flags.prefix + ').+\\\.csv$');

	if (flags.dir) {
		console.log('[DIR]', flags.dir);
		recursiveFileProccessor(flags.dir, regexpr, filename => decodeFile(key, filename))
	}

	if (flags.file) {
		let file = path.resolve(flags.file);
		console.log('[FILE]', file);

		if (prefixCheck({name: file}, regexpr)) {
			decodeFile(key, flags.file)
		} else {
			console.log('File is already decrypted')
		}
	}
})();