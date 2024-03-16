async function uploadFile(host, username, verificationCode, file, onSuccess) {
    try {
        // 验证用户身份和验证码
        const authResponse = await fetch('https://upload.s.7c7.icu/auth', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, verificationCode })
        });

        if (!authResponse.ok) {
            alert('Invalid username or verification code.');
            return;
        }

        // 获取token和系统生成的密码
        const authData = await authResponse.json();
        const token = authData.token;

        const password = generateSecurePassword();

        // 读取文件内容
        const reader = new FileReader();
        reader.onload = async function() {
            const fileContent = reader.result;
            const alg = "deflate+aes+base64";

            // 执行文件加密操作
            const encryptedData = await encryptFile(fileContent, password, alg);

            // 生成 meta
            const meta = {
                schema: 1,
                alg: alg,
                size: file.size,
                filename: base64Encode(file.name),
                hash: {
                    sha256: calculateBlobHash(fileContent, 'SHA-256');
                    sha512: calculateBlobHash(fileContent, 'SHA-512');
                }
            };

            // 上传加密后的文件
            const uploadResponse = await fetch('https://upload.s.7c7.icu/upload-file', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                body: new Blob([base64Encode(JSON.stringify(meta)), '.', encryptedData])
            });

            if (uploadResponse.ok) {
                const slug = uploadResponse.json().slug;
                const url = `${host}/${slug}#${password}`;
                onSuccess(url);
            } else {
                console.error(`${uploadResponse.status} ${uploadResponse.statusText}: ${uploadResponse.json().message}`)
                alert('An error occurred during file upload.');
            }
        };
        reader.readAsArrayBuffer(file);
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred during file upload. Please try again.');
    }
});

// 文件加密函数
async function encryptFile(fileContent, password, operations) {
    // 默认操作为 "deflate+aes+base64"

    // 根据操作执行文件加密操作
    let encryptedData = fileContent;
    const operationsArr = operations.split("+");
    for (const operation of operationsArr) {
        switch (operation) {
            case "deflate":
                encryptedData = await deflateFile(encryptedData);
                break;
            case "aes":
                encryptedData = await aesEncrypt(encryptedData, password);
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
async function aesEncrypt(data, password) {
    const encryptedData = CryptoJS.AES.encrypt(data, password).toString();
    return encryptedData;
}

// 执行base64操作的函数
async function base64Encode(data) {
    const base64EncodedData = btoa(String.fromCharCode.apply(null, new Uint8Array(data)));
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
