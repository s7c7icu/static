// 解析 URL 中的 slug 和 password
const urlParams = new URLSearchParams(window.location.search);
const meta = urlParams.get('meta');
const slug = urlParams.get('slug');
const password = window.location.hash;

// 构建 META 数据的 URL
const metaUrl = `${meta}/${slug[0]}/${slug}.json`;

// 获取 META 数据
async function getMeta() {
    const response = await fetch(metaUrl);
    if (!response.ok) {
        throw new Error('Failed to fetch meta data');
    }
    return response.json();
}

// 下载文件
async function downloadFile(data, filename) {
    const blob = new Blob([data]);
    const url = window.URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// 主函数
async function main(feedback) {
    try {
        feedback({name: 'Acquiring Meta'});
        // 获取 META 数据
        const meta = await getMeta();

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
            fileData = await response.arrayBuffer();
        } else if (meta.data.base64) {
            // 如果存在 base64 字段，则进行 base64 解码
            fileData = base64Decode(meta.data.base64);
        } else if (meta.data.raw) {
            // 如果存在 raw 字段，则直接使用该字段的值
            fileData = meta.data.raw;
        } else {
            // 否则视为空文件
            fileData = '';
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
                    fileData = decrypt(fileData, password);
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
        const fileHash = await crypto.subtle.digest('SHA-512', new TextEncoder().encode(fileData));

        // 检查哈希值是否与给定的相同
        if (!compareHash(fileHash, meta.hash)) {
            throw new Error('Hash mismatch');
        }

        feedback({name: 'Downloading'});
        // 下载文件
        downloadFile(fileData, meta.filename || `${slug}.bin`);
    } catch (error) {
        console.error('Error:', error.message);
    }
}

// 校验 META 数据的合法性
function validateMeta(meta) {
    if (!meta.schema || meta.schema !== 1) {
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
function compareHash(hash1, hash2) {
    // 将哈希值转换为字符串
    const hash1String = Array.from(new Uint8Array(hash1)).map(b => b.toString(16).padStart(2, '0')).join('');
    const hash2String = hash2.replace(/-/g, '').toLowerCase();

    // 比较哈希值是否相等
    return hash1String === hash2String;
}

// 执行base64解码操作的函数
async function base64Decode(base64EncodedData) {
    const binaryString = atob(base64EncodedData);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}
