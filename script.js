// ==========================================
// Core UI & Navigation (main.js)
// ==========================================

// Section Navigation
function showSection(sectionId) {
    document.querySelectorAll('.app-section').forEach(sec => sec.classList.add('d-none'));
    document.getElementById(sectionId).classList.remove('d-none');
    
    // Close mobile navbar if open
    const navbarCollapse = document.getElementById('navbarNav');
    if(navbarCollapse.classList.contains('show')) {
        let bsCollapse = new bootstrap.Collapse(navbarCollapse);
        bsCollapse.hide();
    }
}

// Theme Toggler
const themeToggleBtn = document.getElementById('themeToggle');
themeToggleBtn.addEventListener('click', () => {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', newTheme);
    themeToggleBtn.innerHTML = newTheme === 'dark' ? '<i class="fa-solid fa-sun"></i>' : '<i class="fa-solid fa-moon"></i>';
});

// Init Dashboard Chart (Chart.js)
const ctx = document.getElementById('securityChart').getContext('2d');
new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: ['Secured', 'Vulnerabilities', 'Warnings'],
        datasets: [{
            data: [85, 5, 10],
            backgroundColor: ['#10b981', '#ef4444', '#f59e0b'],
            borderWidth: 0
        }]
    },
    options: { cutout: '75%', plugins: { legend: { display: false } } }
});

// ==========================================
// 1. Password Analyzer (password.js)
// ==========================================
document.getElementById('pwdInput').addEventListener('input', function() {
    const pwd = this.value;
    let score = 0;
    let tips = [];
    
    if(pwd.length > 8) score += 25; else tips.push("Make it longer than 8 characters.");
    if(pwd.match(/[A-Z]/)) score += 25; else tips.push("Add uppercase letters.");
    if(pwd.match(/[0-9]/)) score += 25; else tips.push("Add numbers.");
    if(pwd.match(/[^a-zA-Z0-9]/)) score += 25; else tips.push("Add special characters (e.g., !@#$%).");

    const bar = document.getElementById('pwdProgress');
    const status = document.getElementById('pwdStatus');
    const sugg = document.getElementById('pwdSuggestions');
    
    bar.style.width = score + '%';
    sugg.innerHTML = tips.map(t => `<li>${t}</li>`).join('');

    if(pwd.length === 0) {
        bar.className = 'progress-bar'; status.innerHTML = "Strength: None"; bar.style.width = '0%';
    } else if(score <= 25) {
        bar.className = 'progress-bar bg-danger'; status.innerHTML = "Strength: <span class='text-danger'>Weak</span>";
    } else if(score <= 75) {
        bar.className = 'progress-bar bg-warning'; status.innerHTML = "Strength: <span class='text-warning'>Medium</span>";
    } else {
        bar.className = 'progress-bar bg-success'; status.innerHTML = "Strength: <span class='text-success'>Strong</span>";
        sugg.innerHTML = "<li><span class='text-success'>Great password!</span></li>";
    }
});

// ==========================================
// 2. Encryption Lab (encryption.js)
// ==========================================
function processCrypto(action) {
    const method = document.getElementById('cryptoMethod').value;
    const key = document.getElementById('cryptoKey').value;
    const input = document.getElementById('cryptoInput').value;
    const output = document.getElementById('cryptoOutput');

    try {
        if(method === 'base64') {
            output.value = action === 'encrypt' ? btoa(input) : atob(input);
        } else if(method === 'aes') {
            if(!key) { alert("AES requires a secret key!"); return; }
            output.value = action === 'encrypt' 
                ? CryptoJS.AES.encrypt(input, key).toString()
                : CryptoJS.AES.decrypt(input, key).toString(CryptoJS.enc.Utf8);
        } else if(method === 'caesar') {
            let shift = parseInt(key) || 3;
            if(action === 'decrypt') shift = (26 - shift) % 26;
            output.value = input.replace(/[a-zA-Z]/g, c => {
                let base = c <= 'Z' ? 65 : 97;
                return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
            });
        }
    } catch (e) {
        output.value = "Error: Invalid input or key for decryption.";
    }
}

// ==========================================
// 3. Hash Generator (hash.js)
// ==========================================
document.getElementById('hashInput').addEventListener('input', function() {
    const text = this.value;
    document.getElementById('hashMd5').value = text ? CryptoJS.MD5(text).toString() : '';
    document.getElementById('hashSha1').value = text ? CryptoJS.SHA1(text).toString() : '';
    document.getElementById('hashSha256').value = text ? CryptoJS.SHA256(text).toString() : '';
});

// ==========================================
// 4. URL Security Analyzer (url.js)
// ==========================================
function analyzeURL() {
    const urlStr = document.getElementById('urlInput').value;
    const resultsDiv = document.getElementById('urlResults');
    const scoreSpan = document.getElementById('urlScore');
    const bar = document.getElementById('urlProgress');
    const findings = document.getElementById('urlFindings');
    
    if(!urlStr) return;
    resultsDiv.classList.remove('d-none');
    let score = 100;
    let risks = [];

    // Basic URL Parsing
    try {
        let url = new URL(urlStr.startsWith('http') ? urlStr : 'http://' + urlStr);
        
        if(url.protocol !== 'https:') { score -= 40; risks.push("<span class='text-danger'>Missing HTTPS encryption. Data sent in plaintext.</span>"); }
        if(/\d+\.\d+\.\d+\.\d+/.test(url.hostname)) { score -= 30; risks.push("<span class='text-danger'>IP address used instead of domain name (Common in phishing).</span>"); }
        if((url.hostname.match(/\./g) || []).length > 2) { score -= 15; risks.push("<span class='text-warning'>Multiple subdomains detected (e.g., login.paypal.com.scam.net).</span>"); }
        
        let suspWords = ['login', 'verify', 'update', 'secure', 'account', 'banking'];
        suspWords.forEach(word => {
            if(urlStr.toLowerCase().includes(word)) { score -= 10; risks.push(`<span class='text-warning'>Suspicious keyword found: '${word}'.</span>`); }
        });

        if(risks.length === 0) risks.push("<span class='text-success'>No obvious threats detected. URL structure looks standard.</span>");

    } catch (e) {
        score = 0; risks.push("<span class='text-danger'>Invalid URL format.</span>");
    }

    score = Math.max(0, score);
    scoreSpan.innerText = score;
    bar.style.width = score + '%';
    bar.className = `progress-bar ${score > 70 ? 'bg-success' : score > 40 ? 'bg-warning' : 'bg-danger'}`;
    findings.innerHTML = risks.map(r => `<li class="list-group-item bg-transparent text-light border-secondary">${r}</li>`).join('');
}

// ==========================================
// 5. QR Code Analyzer (qr.js)
// ==========================================
document.getElementById('qrInput').addEventListener('change', function(e) {
    const file = e.target.files[0];
    if(!file) return;
    const reader = new FileReader();
    reader.onload = function(event) {
        const img = new Image();
        img.onload = function() {
            const canvas = document.getElementById('qrCanvas');
            const ctx = canvas.getContext('2d');
            canvas.width = img.width; canvas.height = img.height;
            ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "dontInvert" });
            
            const resBox = document.getElementById('qrResult');
            if(code) {
                resBox.className = 'alert alert-success glass-input';
                resBox.innerHTML = `<strong>Decoded Data:</strong> <br><span class="text-break">${code.data}</span>`;
            } else {
                resBox.className = 'alert alert-danger glass-input';
                resBox.innerText = "No QR code found in the image.";
            }
        };
        img.src = event.target.result;
    };
    reader.readAsDataURL(file);
});

// ==========================================
// 6. Metadata Viewer (metadata.js)
// ==========================================
document.getElementById('exifInput').addEventListener('change', function(e) {
    const file = e.target.files[0];
    if(!file) return;
    const table = document.getElementById('exifTable');
    const tbody = document.getElementById('exifBody');
    const noneText = document.getElementById('exifNone');

    EXIF.getData(file, function() {
        const allTags = EXIF.getAllTags(this);
        tbody.innerHTML = '';
        if(Object.keys(allTags).length === 0) {
            table.classList.add('d-none'); noneText.classList.remove('d-none');
        } else {
            noneText.classList.add('d-none'); table.classList.remove('d-none');
            const targetTags = ['Make', 'Model', 'DateTime', 'GPSLatitude', 'GPSLongitude', 'Software'];
            targetTags.forEach(tag => {
                if(allTags[tag]) {
                    tbody.innerHTML += `<tr><td>${tag}</td><td>${allTags[tag]}</td></tr>`;
                }
            });
            if(tbody.innerHTML === '') tbody.innerHTML = `<tr><td colspan="2">Metadata exists but no common privacy-sensitive tags (GPS/Camera) found.</td></tr>`;
        }
    });
});

// ==========================================
// 7. Phishing Detector (phishing.js)
// ==========================================
function analyzePhishing() {
    const text = document.getElementById('phishInput').value.toLowerCase();
    const resultBox = document.getElementById('phishResult');
    const levelText = document.getElementById('phishLevel');
    const expText = document.getElementById('phishExplanation');
    if(!text) return;

    const redFlags = ['urgent', 'immediate action', 'verify your account', 'suspended', 'password', 'click here', 'winner', 'lottery', 'bank', 'ssn', 'social security'];
    let hits = 0;
    let foundWords = [];

    redFlags.forEach(flag => {
        if(text.includes(flag)) { hits++; foundWords.push(flag); }
    });

    resultBox.classList.remove('d-none');
    if(hits === 0) {
        resultBox.className = 'alert alert-success glass-input mt-3';
        levelText.innerHTML = '<i class="fa-solid fa-check-circle"></i> Safe (Low Risk)';
        expText.innerText = "No common phishing trigger words detected. However, always verify the sender.";
    } else if(hits < 3) {
        resultBox.className = 'alert alert-warning glass-input mt-3 text-dark';
        levelText.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Suspicious (Medium Risk)';
        expText.innerText = `Contains ${hits} suspicious phrase(s): ${foundWords.join(', ')}. Proceed with caution.`;
    } else {
        resultBox.className = 'alert alert-danger glass-input mt-3';
        levelText.innerHTML = '<i class="fa-solid fa-skull-crossbones"></i> High Risk Phishing Attempt!';
        expText.innerText = `Contains ${hits} major red flags: ${foundWords.join(', ')}. Do NOT click links or download attachments.`;
    }
}
// This existing snippet automatically handles the new 'about' section string passed from the HTML onClick event
function showSection(sectionId) {
    document.querySelectorAll('.app-section').forEach(sec => sec.classList.add('d-none'));
    document.getElementById(sectionId).classList.remove('d-none');
    
    // Auto-closes mobile menu dropdown seamlessly
    const navbarCollapse = document.getElementById('navbarNav');
    if(navbarCollapse.classList.contains('show')) {
        let bsCollapse = new bootstrap.Collapse(navbarCollapse);
        bsCollapse.hide();
    }
}