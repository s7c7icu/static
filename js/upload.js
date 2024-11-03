(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        // AMD
        define(['pako', 'Base64', 'nacl', 'CryptoJS'], factory);
    } else if (typeof module === 'object' && module.exports) {
        // CommonJS
        module.exports = factory(require('pako'), require('js-base64').Base64, require('tweetnacl'), require('crypto-js'));
    } else {
        // Browser globals (root is window)
        root.uploadS7c7icu = factory(root.pako, root.Base64, root.nacl, root.CryptoJS);
    }
}(typeof self !== 'undefined' ? self : this, function (pako, Base64, nacl, CryptoJS) {
    // Your module code here using pako, Base64, nacl, CryptoJS
    
    function isAllASCII(uint8Array) {
        for (let i = 0; i < uint8Array.length; i++) {
            if (uint8Array[i] > 127) {
                return false; // 如果有任何字符超出 ASCII 范围，返回 false
            }
        }
        return true; // 如果所有字符均在 ASCII 范围内，返回 true
    }
    
    /**
     * 
     * @param {string | null} host Download Portal, used in returned URL. If left `null`, returns an object
     * containing `slug` and `pasword`.
     * @param {string} apiRoot URL root of Upload API
     * @param {string} username (for future use)
     * @param {string | number} verificationCode TOTP verification code 
     * @param {Blob} file The uploaded file
     * @param {string} filename File name that is displayed on Meta
     * @returns {string | { slug: string, password: string }} The download URL or an object containing
     * `slug` and password.
     */
    async function uploadFile(host, apiRoot, username /* future use */, verificationCode, file, filename) {
        return new Promise(async (resolve, reject) => {
            try {
                // 验证用户身份和验证码
                const authResponse = await fetch(apiRoot + '/api/auth', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, code: verificationCode })
                });
        
                if (!authResponse.ok) {
                    reject({ message: 'Invalid username or verification code.' , stack: await authResponse.text() });
                    return;
                }
        
                // 获取token和系统生成的密码
                const authData = await authResponse.json();
                const token = authData.token;
        
                const [key, nonce, salt] = [nacl.randomBytes(32), nacl.randomBytes(24), nacl.randomBytes(32)];
                const password = Base64.fromUint8Array(new Uint8Array([...nonce, ...key]), true);
                
        
                // 读取文件内容
                const reader = new FileReader();
                reader.onload = async function() {
                    const fileContent = new Uint8Array(reader.result);
                    const alg = "deflate+aes";
        
                    // 执行文件加密操作
                    const encryptedData = encryptFile(fileContent, key, nonce, alg);
                    const saltedOriginalContent = new Uint8Array([...fileContent, ...salt]);
        
                    // 生成 meta
                    const meta = {
                        schema: 3,
                        alg,
                        size: file.size,
                        filename: Base64.encode(filename),
                        hash: {
                            sha256: await calculateBlobHash(saltedOriginalContent, 'SHA-256'),
                            sha512: await calculateBlobHash(saltedOriginalContent, 'SHA-512')
                        },
                        salter: {
                            name: 's7c7icu:postappend-v0',
                            salt: Base64.fromUint8Array(salt),
                        },
                    };
        
                    // Upload Data
                    if (encryptedData.byteLength <= 4096) {
                        if (isAllASCII(encryptedData)) {
                            meta.data = { raw: new TextDecoder('ascii').decode(encryptedData) };
                        } else {
                            meta.data = { base64: Base64.fromUint8Array(encryptedData) }
                        }
                    } else {
                        const dataResponse = await fetch(apiRoot + '/api/upload/data', {
                            method: 'POST',
                            headers: {
                                'Authorization': 'Bearer ' + token
                            },
                            body: new Blob([encryptedData])
                        });
        
                        if (!dataResponse.ok) {
                            throw new Error('Failed to push data: ' + await dataResponse.text());
                        }
        
                        meta.data = { fetch: (await dataResponse.json()).fullUrl };
                    }
        
                    // Upload Meta
                    const metaResponse = await fetch(apiRoot + '/api/upload/meta', {
                        method: 'POST',
                        headers: {
                            Authorization: 'Bearer ' + token
                        },
                        body: new Blob([JSON.stringify(meta)])
                    });
                    if (!metaResponse.ok) {
                        throw new Error('Failed to push meta: ' + await metaResponse.text());
                    }
                    
                    var slug = (await metaResponse.json()).slug;
                    if (host) {
                        var url = host + '/' + slug + '#' + password;
                        resolve(url);
                    } else {
                        resolve({ slug, password });
                    }
                };
                reader.readAsArrayBuffer(file);
            } catch (error) {
                console.error(error);
                reject(error);
            }
        });
    };
    
    // 文件加密函数
    /**
     * @returns {Uint8Array}
     */
    function encryptFile(fileContent, key, nonce, operations) {
        // 默认操作为 "deflate+aes"
    
        // 根据操作执行文件加密操作
        let encryptedData = fileContent;
        const operationsArr = operations.split("+");
        for (const operation of operationsArr) {
            switch (operation) {
                case "deflate":
                    encryptedData = deflateFile(encryptedData);
                    break;
                case "aes":
                    encryptedData = aesEncrypt(encryptedData, key, nonce);
                    break;
                case "base64":
                    encryptedData = base64Encode(encryptedData);
                    break;
                default:
                    console.error("Unsupported operation:", operation);
            }
        }
        return encryptedData;
    }
    
    // 执行deflate操作的函数
    function deflateFile(data) {
        const compressedData = pako.deflate(data);
        return compressedData;
    }
    
    // 执行aes操作的函数
    function aesEncrypt(data, key, nonce) {
        const encryptedData = nacl.secretbox(data, nonce, key);
        return encryptedData;
    }
    
    // 执行base64操作的函数
    function base64Encode(data) {
        const base64EncodedData = Base64.fromUint8Array(data);
        return new TextEncoder().encode(base64EncodedData);
    }
    
    async function calculateBlobHash(arrayBuffer, hashType) {
        const hashBuffer = await crypto.subtle.digest(hashType, arrayBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

    return {
    	uploadFile
    };
}));
