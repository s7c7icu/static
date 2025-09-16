(function (global, factory) {
    if (typeof exports === 'object' && typeof module !== 'undefined') {
        // CommonJS (Node.js) 环境
        module.exports = factory(
            require('pako'),
            require('js-base64'),
            require('tweetnacl'),
            require('crypto-js'),
            requier('jszip'),
        );
    } else if (typeof define === 'function' && define.amd) {
        // AMD 环境（如 RequireJS）
        define(['pako', 'js-base64', 'tweetnacl', 'crypto-js', 'jszip'], factory);
    } else {
        // 浏览器全局环境
        global.s7c7icu = factory(
            global.pako,
            global.Base64,
            global.nacl,
            global.CryptoJS,
            global.JSZip,
        );
    }
}(typeof self !== 'undefined' ? self
    : typeof window !== 'undefined' ? window
        : typeof global !== 'undefined' ? global
            : this, function (pako, Base64, nacl, CryptoJS, JSZip) {

    // 你的模块代码在这里

    const SUPPORTED_MAX_SCHEMA = 4;

    // 获取 META 数据
    async function getMeta(info) {
        const { meta, slug, password } = info;
        // 构建 META 数据的 URL
        const metaUrl = `${meta}/${slug[0]}/${slug}.json`;

        const response = await fetch(metaUrl);
        if (!response.ok) {
            throw new Error('Failed to fetch meta data');
        }
        return response.json();
    }
    // 主函数
    /**
     * @param {{meta: string, slug: string, password: string}} info
     * The information object of a file on the service.
     * @param {function | null} fileReceiver The callback: `(blob, filename) => void`.
     * @param {function} feedback Log receiver, with an `object` parameter, in which field
     * `name` must be included. If `name` is `"error"` (case-insensitive) then it must be
     * treated as an error.
     * @returns {{blob: Blob, filename: string} | null} Null if `fileReceiver` is non-null,
     * otherwise returns the object.
    */
    async function main(info, fileReceiver, feedback) {
        try {
            feedback({name: 'Acquiring Meta'});
            // 获取 META 数据
            const meta = await getMeta(info);

            feedback({name: 'Checking Meta'});
            // 检查 META 数据的合法性
            if (!validateMeta(meta)) {
                throw new Error('Invalid meta data');
            }

            feedback({name: 'Acquiring Data'});
            // 获取文件数据
            let fileData;
            if (meta.data.fetch) {
                // 如果存在 fetch 字段，则从指定 URL 拉取数据
                feedback({name: 'Fetching Data', detail: "downloading from " + meta.data.fetch});
                const response = await fetch(meta.data.fetch);
                if (!response.ok) {
                    throw new Error('Failed to fetch file data');
                }
                fileData = new Uint8Array(await response.arrayBuffer());
            } else if (meta.data.base64) {
                // 如果存在 base64 字段，则进行 base64 解码
                fileData = Base64.toUint8Array(meta.data.base64);
            } else if (meta.data.raw) {
                // 如果存在 raw 字段，则直接使用该字段的值
                fileData = new TextEncoder().encode(meta.data.raw);
            } else {
                // 否则视为空文件
                fileData = new Uint8Array();
            }

            feedback({name: 'Decrypting'});
            // 获取算法和密码
            const algorithms = meta.alg.split('+').reverse();

            // 逆向解码
            algorithms.forEach(algorithm => {
                switch (algorithm) {
                    case 'deflate':
                        // 解压缩
                        fileData = inflate(fileData);
                        break;
                    case 'aes':
                        // 解密
                        /* Schema 1 BEGIN: data中含有前导24位，当删 */
                        if (meta.schema == 1) fileData = new Uint8Array(fileData).slice(24);
                        /* Schema 1 END */
                        fileData = decrypt(fileData, info.password);
                        break;
                    case 'base64':
                        // base64 解码
                        fileData = base64Decode(fileData);
                        break;
                    default:
                        throw new Error(`Unknown algorithm: ${algorithm}`);
                }
            });

            /* Schema 4 BEGIN: Flag "filename-preappend" */
            if (meta.schema >= 4 && meta.flags && meta.flags.includes('filename-preappend')) {
                const filenameLength = readInt16(fileData.slice(0, 2));
                meta.filename = Base64.fromUint8Array(fileData.slice(2, filenameLength + 2));
                fileData = fileData.slice(filenameLength + 2);
            }
            /* Schema 4 END */

            feedback({name: 'Verifying'});
            // 验证文件
            if (meta.size >= 0) {
                const fileSize = fileData.byteLength || fileData.length;
                if (fileSize !== meta.size) {
                    throw new Error('File size mismatch');
                }
            }

            // 检查哈希值是否与给定的相同
            /* Schema 2 BEGIN: 未引入salter */
            const hashingResult = compareHashSalted(fileData, meta.hash, meta.schema < 3 ? null : meta.salter);
            /* Schema 2 END */

            if (hashingResult) {
                if (hashingResult.unknownAlgorithm) throw new Error('Unknown algorithm: ' + hashingResult.alg);
                throw new Error(`${hashingResult.alg} hash mismatch: expected ${hashingResult.expectedHash}, got ${hashingResult.calculatedHash}`);
            }

            feedback({name: 'Downloading'});
            // 下载文件
            const [blob, filename] = [new Blob([fileData]), meta.filename ? Base64.decode(meta.filename) : `${slug}.bin`];

            /* Schema 4 BEGIN: Flag "zipindex" */
            if (meta.schema >= 4 && meta.flags && meta.flags.includes('zipindex')) {
                blob = parseZipIndex(blob, feedback, meta);
            }
            /* Schema 4 END */

            if (!fileReceiver) return { blob, filename };
            fileReceiver(blob, filename);
        } catch (error) {
            feedback({
                name: 'Error',
                detail: error.message + '\n' + error.stack + ' *',
                errorObject: error
            });
            //throw error;
        }
    }

    // 校验 META 数据的合法性
    function validateMeta(meta) {
        if (!meta.schema || typeof meta.schema !== 'number' || meta.schema <= 0 || meta.schema > SUPPORTED_MAX_SCHEMA) {
            return false;
        }
        if (!meta.alg || !meta.alg.includes('aes')) {
            return false;
        }
        if (!meta.hash || Object.keys(meta.hash).length === 0) {
            return false;
        }
        if (meta.schema >= 4) {
            if (meta.flags && !Array.isArray(meta.flags)) {
                return false;
            }
        }
        return true;
    }

    const salters = {
        none: (_saltConf) => compareHash,
        's7c7icu:postappend-v0': function(saltConf) {
            let salt = Base64.toUint8Array(saltConf.salt);
            return (fileData, hashObject) => {
                let concated = new Uint8Array([...fileData, ...salt]);
                return compareHash(concated, hashObject);
            }
        }
    }
    
    const compareHashSalted = function(fileData, hashObject, salterObject) {
        let salter = (function() {
            if (!salterObject || !salterObject.name || !(salterObject.name in salters))
                return salters.none;
            return salters[salterObject.name];
        })();
        return salter(salterObject)(fileData, hashObject);
    }

    // 比较哈希值
    const compareHash = (function() {
        const sha3funcFactory = (outputLength) => (data) => CryptoJS.SHA3(data, { outputLength });
        const knownHashAlgorithms = {
            sha512: CryptoJS.SHA512,
            sha256: CryptoJS.SHA256,
            sha384: CryptoJS.SHA384,
            sha3:   CryptoJS.SHA3,
            sha3_256: sha3funcFactory(256),
            sha3_384: sha3funcFactory(384)
        };
        const algorithmAlias = {
            sha512: ['sha-512', 'sha_512'],
            sha256: ['sha-256', 'sha_256'],
            sha384: ['sha-384', 'sha_384'],
            sha3: ['sha3-512', 'sha3_512'],
            sha3_256: ['sha3-256'],
            sha3_384: ['sha3-384']
        };
        for (const [key, aliases] of Object.entries(algorithmAlias)) {
            aliases.forEach(alias => knownHashAlgorithms[alias] = knownHashAlgorithms[key]);
        }

        function compareHash0(fileData, hashObject) {
            for (const [alg, expectedHash] of Object.entries(hashObject)) {
                const fun = knownHashAlgorithms[alg];
                if (!fun) return { alg, expectedHash, calculatedHash: '0', unknownAlgorithm: true }
                const calculatedHash = knownHashAlgorithms[alg](CryptoJS.lib.WordArray.create(fileData)).toString();
                if (expectedHash !== calculatedHash) {
                    return { alg, expectedHash, calculatedHash };
                }
            }
        }

        return compareHash0;
    })();

    /**
     * @param {Uint8Array} u8array 
     * @returns {DataView}
     */
    function readInt16(u8array) {
        // Big Endian
        return new DataView(u8array.buffer, 0, 2).getInt16();
    }

    // 执行base64解码操作的函数
    function base64Decode(base64EncodedData) {
        const buffer = new TextDecoder('latin1').decode(base64EncodedData);
        return Base64.toUint8Array(buffer);
    }

    // inflate操作
    const inflate = pako.inflate;

    // AES decrypt，使用Salsa20算法
    // 密钥de-base64后，前8位是nonce，后32位是key
    function decrypt(buffer, password) {
        var rawPassword = Base64.toUint8Array(password);
        var key = rawPassword.slice(24);
        var nonce = rawPassword.slice(0, 24);

        const box = nacl.secretbox;
        return box.open(new Uint8Array(buffer), nonce, key);
    }

      // 辅助函数：向zip对象添加一个文件
    async function addFileToZip(zip, fileName, data, defaultMeta, feedback) {
        //if (isSkippable(data)) return;
    
        if (fileName.endsWith('/')) {
            zip.folder(fileName.slice(0, -1));
        } else {
            if (data.fetch) {
                if (!data.fetch.startsWith('s7c7icu://')) {
                    const response = await fetch(data.fetch);
                    if (!response.ok) {
                        console.error(`Failed to fetch ${fileName}:`, response.status, response.statusText);
                        return;
                    }
                    const blob = await response.blob();
                    zip.file(fileName, blob);
                } else {
                    var [slug, password, meta] = data.fetch.slice(0, 's7c7icu://'.length).split('/');
                    meta = meta ? decodeURIComponent(meta) : defaultMeta;
                    const res = await main({ slug, password, meta }, null, feedback);
                    zip.file(fileName, res.blob);
                }
            } else if (data.base64) {
                zip.file(fileName, data.base64, {base64:true});
            } else if (data.raw) {
                zip.file(fileName, data.raw);
            } else {
                zip.file(fileName, '');
            }
        }
    }
    
    /**
     * @param {Blob} blob input blob
     * @param {function} feedback the log receiver
     * @param {string} defaultMeta default meta url
     * @returns {Blob} the zip file
     */
    async function parseZipIndex(blob, feedback, defaultMeta) {
        const json = JSON.parse(await blob.text());
        if (typeof json !== 'object') {
            throw new Error("ZipIndex should be an object");
        }
        const zip = new JSZip();

        for (const [fileName, data] of Object.entries(json)) {
            feedback({name: 'Adding file to zip', detail: fileName});
            await addFileToZip(zip, fileName, data, defaultMeta, feedback);
        }

        feedback({name: 'Generating archive'});
        return zip.generateAsync({type:'blob',compression:'DEFLATE',compressionOptions:{level:5}});
    }

    return { main };
}));
