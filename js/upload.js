function combineArray(array1, array2) {
    const combinedArray = new Uint8Array(array1.length + array2.length);
    combinedArray.set(array1, 0);
    combinedArray.set(array2, array1.length);
    return combinedArray;
}

function isAllASCII(uint8Array) {
    for (let i = 0; i < uint8Array.length; i++) {
        if (uint8Array[i] > 127) {
            return false; // 如果有任何字符超出 ASCII 范围，返回 false
        }
    }
    return true; // 如果所有字符均在 ASCII 范围内，返回 true
}

async function uploadFile(host, username /* future use */, verificationCode, file, onSuccess) {
    try {
        // 验证用户身份和验证码
        const authResponse = await fetch('https://upload.s.7c7.icu/api/auth', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, code: verificationCode })
        });

        if (!authResponse.ok) {
            alert('Invalid username or verification code.');
            return;
        }

        // 获取token和系统生成的密码
        const authData = await authResponse.json();
        const token = authData.token;

        const [key, nonce] = [nacl.randomBytes(32), nacl.randomBytes(24)];
        const password = Base64.fromUint8Array(combineArray(nonce, key));
        

        // 读取文件内容
        const reader = new FileReader();
        reader.onload = async function() {
            const fileContent = new Uint8Array(reader.result);
            const alg = "deflate+aes";

            // 执行文件加密操作
            const encryptedData = await encryptFile(fileContent, key, nonce, alg);

            // 生成 meta
            const meta = {
                schema: 2,
                alg,
                size: file.size,
                filename: base64Encode(file.name),
                hash: {
                    sha256: calculateBlobHash(fileContent, 'SHA-256'),
                    sha512: calculateBlobHash(fileContent, 'SHA-512')
                }
            };

            // Upload Data
            if (encryptedData.byteLength <= 4096) {
                if (isAllASCII(encryptedData)) {
                    meta.data = { raw: new TextDecoder('ascii').decode(encryptedData) };
                } else {
                    meta.data = { base64: Base64.encode(encryptedData) }
                }
            } else {
                const dataResponse = await fetch('https://upload.s.7c7.icu/api/upload/data', {
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
            const metaResponse = await fetch('https://upload.s.7c7.icu/api/upload/meta', {
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
            var url = host + '/' + slug + '#' + password;
            onSuccess(url);
        };
        reader.readAsArrayBuffer(file);
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred during file upload. Please try again.');
    }
};

// 文件加密函数
/**
 * @returns {Promise<Uint8Array>}
 */
async function encryptFile(fileContent, key, nonce, operations) {
    // 默认操作为 "deflate+aes"

    // 根据操作执行文件加密操作
    let encryptedData = fileContent;
    const operationsArr = operations.split("+");
    for (const operation of operationsArr) {
        switch (operation) {
            case "deflate":
                encryptedData = await deflateFile(encryptedData);
                break;
            case "aes":
                encryptedData = await aesEncrypt(encryptedData, key, nonce);
                break;
            case "base64":
                encryptedData = await base64Encode(encryptedData);
                break;
            default:
                console.error("Unsupported operation:", operation);
        }
    }
    return encryptedData;
}

// 执行deflate操作的函数
async function deflateFile(data) {
    const compressedData = pako.deflate(data);
    return compressedData;
}

// 执行aes操作的函数
async function aesEncrypt(data, key, nonce) {
    const encryptedData = nacl.secretbox(data, nonce, key);
    return encryptedData;
}

// 执行base64操作的函数
async function base64Encode(data) {
    const base64EncodedData = Base64.toUint8Array(data);
    return base64EncodedData;
}

function generateSecurePassword() {
    var charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    var password = "";
    var passwordLength = Math.floor(Math.random() * 3) + 7; // 生成7到9之间的随机长度

    var values = new Uint32Array(passwordLength);
    getRandomValues(values);

    for (var i = 0; i < passwordLength; i++) {
        var randomIndex = values[i] % charset.length;
        password += charset[randomIndex];
    }

    return password;
}

async function calculateBlobHash(arrayBuffer, hashType) {
    const hashBuffer = await crypto.subtle.digest(hashType, arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
    return hashHex;
}
