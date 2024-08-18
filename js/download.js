(function (global, factory) {
    if (typeof exports === 'object' && typeof module !== 'undefined') {
        // CommonJS (Node.js) 环境
        module.exports = factory(
            require('pako'),
            require('js-base64'),
            require('tweetnacl'),
            require('crypto-js')
        );
    } else if (typeof define === 'function' && define.amd) {
        // AMD 环境（如 RequireJS）
        define(['pako', 'js-base64', 'tweetnacl', 'crypto-js'], factory);
    } else {
        // 浏览器全局环境
        global.s7c7icu = factory(
            global.pako,
            global.Base64,
            global.nacl,
            global.CryptoJS
        );
    }
}(typeof self !== 'undefined' ? self
    : typeof window !== 'undefined' ? window
        : typeof global !== 'undefined' ? global
            : this, function (pako, Base64, nacl, CryptoJS) {

    // 你的模块代码在这里

    const SUPPORTED_MAX_SCHEMA = 2;

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

            feedback({name: 'Verifying'});
            // 验证文件
            if (meta.size >= 0) {
                const fileSize = fileData.byteLength || fileData.length;
                if (fileSize !== meta.size) {
                    throw new Error('File size mismatch');
                }
            }

            // 计算文件的哈希值
            // 暂且先实现SHA512的部分
            const fileHash = CryptoJS.SHA512(CryptoJS.lib.WordArray.create(fileData)).toString();

            // 检查哈希值是否与给定的相同
            if (!compareHash(fileHash, meta.hash.sha512)) {
                throw new Error('Hash mismatch: ' + `${fileHash} ≠ ${meta.hash.sha512}`);
            }

            feedback({name: 'Downloading'});
            // 下载文件
            fileReceiver(new Blob([fileData]), meta.filename ? Base64.decode(meta.filename) : `${slug}.bin`);
        } catch (error) {
            feedback({name: 'Error', detail: error.message + error.stack + ' *'});
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
        return true;
    }

    // 比较哈希值
    function compareHash(hash1String, hash2String) {
        return hash1String === hash2String;
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

    return { main };
}));
