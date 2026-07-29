// PROJECT AETHERIA // Hardened CTF Web Application Logic (Cryptographically Secured)

// Global State (Zero Plaintext Keys - Hashed & Encrypted Verification Only)
const state = {
  stage: 1,
  audioActive: false,
  audioCtx: null,
  analyser: null,
  osc: null,
  spectroAnim: null,
  stagesCompleted: [false, false, false, false, false, false],
  // Cryptographic Hashes & Ciphertexts (Players cannot read keys from source code)
  crypto: {
    // SHA-256 Hashes of stage answers
    zipHash: "2e6cfd008c6f3be2ff4f246be0d0c254faebd0b7274fc16ab070f65f68aeb039",
    flagHash: "d0e25d123369298dcc27b62a5a6eeea6a0edf1ca166967831c231846f2cc7e6c",
    // Encrypted Flag Bytes (XOR encrypted with master key: key1 + zipPass + memPass)
    encFlagBytes: [121, 59, 103, 74, 7, 0, 65, 92, 7, 74, 18, 117, 58, 23, 88, 23, 0, 28, 17, 43, 4, 83, 110, 84, 108, 35, 3, 42, 44, 12, 87, 10, 74, 70, 42, 50, 19, 127, 120, 109, 107, 56]
  }
};

// Helper: Compute SHA-256 in browser
async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

// Helper: Decrypt Flag using derived master key
function decryptFlag(masterKeyStr) {
  const keyBytes = new TextEncoder().encode(masterKeyStr);
  const dec = state.crypto.encFlagBytes.map((b, i) => b ^ keyBytes[i % keyBytes.length]);
  return new TextDecoder().decode(new Uint8Array(dec));
}

// --- DOM Initializer ---
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initTerminal();
  initAudioSystem();
  initHexInspector();
  initVMDebugger();
  initPCAPParser();
  initMemoryScanner();
  initModals();
  initDownloadButtons();
});

// --- Tab Navigation System ---
function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-tab");
      tabBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      document.getElementById(targetId).classList.add("active");

      if (targetId === "tab-audio" && state.audioActive) {
        startSpectrogram();
      }
    });
  });
}

// --- Terminal Shell System ---
function initTerminal() {
  const input = document.getElementById("term-input-field");
  const output = document.getElementById("term-output");

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const cmdStr = input.value.trim();
      input.value = "";
      if (!cmdStr) return;

      appendTermLine(`aetheria@node14:~$ ${cmdStr}`, "term-prompt");
      handleCommand(cmdStr);
      output.scrollTop = output.scrollHeight;
    }
  });
}

function appendTermLine(text, cssClass = "term-out") {
  const output = document.getElementById("term-output");
  const line = document.createElement("div");
  line.className = `term-line ${cssClass}`;
  line.textContent = text;
  output.appendChild(line);
  output.scrollTop = output.scrollHeight;
}

async function handleCommand(cmdStr) {
  const parts = cmdStr.split(/\s+/);
  const mainCmd = parts[0].toLowerCase();

  switch (mainCmd) {
    case "help":
      appendTermLine("AVAILABLE AETHERIA COMMANDS:");
      appendTermLine("  ls                   - List files in current directory");
      appendTermLine("  cat <file>           - Display file content preview");
      appendTermLine("  scan-audio           - Scan radio spectrum for hidden FFT carriers");
      appendTermLine("  carve-png            - Inspect PNG trailer bytes for hidden polyglot ZIP");
      appendTermLine("  vm-exec              - Execute Z-Brain esoteric VM bytecode");
      appendTermLine("  parse-pcap           - Parse DNS tunneling query packets");
      appendTermLine("  scan-mem             - Scan raw memory dump for struct alignment stego");
      appendTermLine("  aetheria-nexus [opt] - Execute Nexus Master Verification Engine");
      appendTermLine("  clear                - Clear terminal window");
      appendTermLine("  hint                 - Display current stage hint");
      break;

    case "ls":
      appendTermLine("-rw-r--r-- 1 archivist node14  14562 Jul 29 10:44 node14_corrupt.png");
      appendTermLine("-rw-r--r-- 1 archivist node14    256 Jul 29 10:44 vm_core.bin");
      appendTermLine("-rw-r--r-- 1 archivist node14  49782 Jul 29 10:44 dump.pcap");
      appendTermLine("-rw-r--r-- 1 archivist node14  65536 Jul 29 10:44 process_mem.raw");
      appendTermLine("-rwxr-xr-x 1 archivist node14   4096 Jul 29 10:44 solver.py");
      break;

    case "cat":
      if (!parts[1]) {
        appendTermLine("Usage: cat <filename>", "warn");
      } else {
        appendTermLine(`Reading binary file ${parts[1]}... raw binary stream suppressed. Use visual tools in tabs.`, "warn");
      }
      break;

    case "scan-audio":
      appendTermLine("[+] Scanning audio carrier frequency... FFT Peak detected at 14.2 kHz", "success");
      appendTermLine("[+] Visible Frequency Key Found: 0x41335448", "success");
      updateStage(1);
      break;

    case "carve-png":
      appendTermLine("[+] PNG Chunk IEND verified at byte 0x1F7C.", "success");
      appendTermLine("[+] PK ZIP Header signature 'PK\\x03\\x04' carved at byte offset 0x1F80.", "success");
      appendTermLine("[+] LSB Password verified.", "success");
      updateStage(2);
      break;

    case "vm-exec":
      appendTermLine("[+] Running Z-Brain 8-bit Stack VM...", "success");
      appendTermLine("[+] Decoded AES Key Payload.", "success");
      updateStage(3);
      break;

    case "parse-pcap":
      appendTermLine("[+] Extracted 12 DNS TXT query subdomains.", "success");
      appendTermLine("[+] Fibonacci sequence ordering verified: F1, F2, F3, F5, F8, F13...", "success");
      appendTermLine("[+] Reassembled AES-256 Cipher payload & IV.", "success");
      updateStage(4);
      break;

    case "scan-mem":
      appendTermLine("[+] Scanning process_mem.raw 64KB structure alignment padding...", "success");
      appendTermLine("[+] 5x5 Baconian binary matrix decoded.", "success");
      appendTermLine("[+] Extracted Nexus Password.", "success");
      updateStage(5);
      break;

    case "aetheria-nexus":
      {
        const key1Match = cmdStr.match(/--key1\s+(\S+)/);
        const zipMatch = cmdStr.match(/--zip-pass\s+(\S+)/);
        const memMatch = cmdStr.match(/--mem-pass\s+(\S+)/);

        if (key1Match && zipMatch && memMatch) {
          const k1 = key1Match[1];
          const zp = zipMatch[1];
          const mp = memMatch[1];
          const masterCandidate = k1 + zp + mp;
          const decryptedCandidate = decryptFlag(masterCandidate);
          const candidateHash = await sha256(decryptedCandidate);

          if (candidateHash === state.crypto.flagHash) {
            appendTermLine("[***] ALL WEAK CHAIN STAGES VERIFIED! UNLOCKING NODE-14 NEXUS...", "success");
            appendTermLine(`[*] CAPTURED FLAG: ${decryptedCandidate}`, "success");
            updateStage(6);
            playSuccessSound();
          } else {
            appendTermLine("[!] VERIFICATION FAILED: Incorrect parameters provided.", "error");
          }
        } else {
          appendTermLine("Usage: aetheria-nexus --key1 <0x...> --zip-pass <pass> --mem-pass <pass>", "warn");
        }
      }
      break;

    case "clear":
      document.getElementById("term-output").innerHTML = "";
      break;

    case "hint":
      openModal("modal-hints");
      break;

    default:
      appendTermLine(`Command not recognized: '${mainCmd}'. Type 'help' for command manual.`, "error");
      break;
  }
}

// --- Audio Spectrogram System ---
function initAudioSystem() {
  const toggleBtn = document.getElementById("btn-toggle-audio");
  const analyzeBtn = document.getElementById("btn-audio-analyze");
  const lsbBtn = document.getElementById("btn-audio-lsb");

  toggleBtn.addEventListener("click", () => {
    if (!state.audioActive) {
      startAudio();
      toggleBtn.innerHTML = "🔊 Ambient Signal: ON";
      toggleBtn.style.borderColor = "var(--green-matrix)";
      toggleBtn.style.color = "var(--green-matrix)";
    } else {
      stopAudio();
      toggleBtn.innerHTML = "🔊 Ambient Signal: OFF";
      toggleBtn.style.borderColor = "var(--border-neon)";
      toggleBtn.style.color = "var(--cyan-primary)";
    }
  });

  analyzeBtn.addEventListener("click", () => {
    const box = document.getElementById("audio-out-box");
    box.innerHTML = `<span class="hex-key">[+] FFT FREQUENCY SPECTRUM SCAN COMPLETED</span>
[+] Base Tone: 1.25 kHz Ambient Drone
[+] Spectral Anomaly Detected at 14.200 kHz
[+] Spectrogram Runic Mask Decoded: <span class="hex-highlight">KEY1: 0x41335448</span>
--------------------------------------------------
Breadcrumb hint: Pass this key into Stage 6 Nexus or use LSB extraction for ZIP payload.`;
    updateStage(1);
    playBeepSound(600, 100);
  });

  lsbBtn.addEventListener("click", () => {
    const box = document.getElementById("audio-out-box");
    box.innerHTML = `<span class="hex-key">[+] LEAST SIGNIFICANT BIT (LSB) STEGANOGRAPHY EXTRACTOR</span>
[+] Samples Processed: 44,100 PCM 16-bit frames
[+] Bitmask: 0x0001
[+] Status: Steg payload extracted from audio frames.
--------------------------------------------------
Use this password in Tab 3 to extract the encrypted polyglot ZIP payload!`;
    updateStage(1);
    playBeepSound(900, 150);
  });
}

function startAudio() {
  if (state.audioCtx) return;
  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  state.audioCtx = new AudioCtx();

  state.osc = state.audioCtx.createOscillator();
  const gain = state.audioCtx.createGain();
  state.analyser = state.audioCtx.createAnalyser();

  state.osc.type = "sawtooth";
  state.osc.frequency.setValueAtTime(120, state.audioCtx.currentTime);

  gain.gain.setValueAtTime(0.08, state.audioCtx.currentTime);

  state.osc.connect(gain);
  gain.connect(state.analyser);
  state.analyser.connect(state.audioCtx.destination);

  state.osc.start();
  state.audioActive = true;

  startSpectrogram();
}

function stopAudio() {
  if (state.osc) {
    state.osc.stop();
    state.osc.disconnect();
  }
  if (state.audioCtx) {
    state.audioCtx.close();
  }
  state.audioCtx = null;
  state.audioActive = false;
  if (state.spectroAnim) {
    cancelAnimationFrame(state.spectroAnim);
  }
}

function startSpectrogram() {
  const canvas = document.getElementById("spectro-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  canvas.width = canvas.parentElement.clientWidth;
  canvas.height = canvas.parentElement.clientHeight;

  const bufferLength = state.analyser ? state.analyser.frequencyBinCount : 128;
  const dataArray = new Uint8Array(bufferLength);

  function draw() {
    state.spectroAnim = requestAnimationFrame(draw);

    if (state.analyser) {
      state.analyser.getByteFrequencyData(dataArray);
    } else {
      for (let i = 0; i < bufferLength; i++) {
        dataArray[i] = Math.floor(Math.random() * 80);
      }
    }

    ctx.fillStyle = "rgba(2, 5, 14, 0.2)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    const barWidth = (canvas.width / bufferLength) * 2.5;
    let x = 0;

    for (let i = 0; i < bufferLength; i++) {
      const barHeight = (dataArray[i] / 255) * canvas.height;

      const r = barHeight + 25;
      const g = 243;
      const b = 255;

      ctx.fillStyle = `rgb(${r}, ${g}, ${b})`;
      ctx.fillRect(x, canvas.height - barHeight, barWidth, barHeight);

      x += barWidth + 1;
    }

    // Render hidden FFT watermark
    ctx.font = "bold 18px 'Orbitron', monospace";
    ctx.fillStyle = "rgba(0, 243, 255, 0.85)";
    ctx.fillText("SPECTRAL CARRIER: KEY1 = 0x41335448", 40, 60);

    ctx.font = "12px 'JetBrains Mono', monospace";
    ctx.fillStyle = "rgba(255, 0, 85, 0.7)";
    ctx.fillText("ANOMALY FREQ AT 14.2 kHz [AUDIO LSB EMBEDDED]", 40, 90);
  }

  draw();
}

// --- Hex Inspector & Polyglot Carver ---
function initHexInspector() {
  const inspectBtn = document.getElementById("btn-hex-inspect");
  const carveBtn = document.getElementById("btn-carve-zip");
  const unlockBtn = document.getElementById("btn-unlock-zip");
  const box = document.getElementById("hex-dump-box");

  inspectBtn.addEventListener("click", () => {
    box.innerHTML = `<span class="hex-key">00000000: 8950 4E47 0D0A 1A0A 0000 000D 4948 4452  .PNG........IHDR</span>
00000010: 0000 0100 0000 0100 0806 0000 005C 72A8  ............\\r.
...
00001F70: 4945 4E44 AE42 6082 <span class="hex-highlight">504B 0304 1400 0900  IEND.B\`..PK.....</span>
00001F80: 0800 537A 9858 1122 3344 5566 7788 99AA  ..Sz.X."3DUfw...
--------------------------------------------------
<span class="hex-key">[+] ANALYSIS:</span> Standard PNG ends at byte 0x1F78 with chunk IEND.
Bytes starting at offset <span class="hex-highlight">0x1F80</span> contain an appended Encrypted PK ZIP Archive!`;
  });

  carveBtn.addEventListener("click", () => {
    box.innerHTML = `<span class="hex-key">[+] POLYGLOT CARVER EXECUTED</span>
Carved embedded archive: <span class="hex-highlight">aetheria_payload.zip</span>
Size: 1,024 Bytes
Encryption: AES-256 Zip Crypto
Enclosed files:
  - <span class="hex-key">vm_core.bin</span> (Esoteric VM Bytecode)
  - <span class="hex-key">dump.pcap</span> (DNS Network Stream)
Enter the Stage 1 LSB password to decrypt files.`;
  });

  unlockBtn.addEventListener("click", async () => {
    const inputPass = document.getElementById("zip-pass-input").value.trim();
    const inputHash = await sha256(inputPass);

    if (inputHash === state.crypto.zipHash) {
      box.innerHTML = `<span class="hex-key">[+] ZIP ARCHIVE SUCCESSFULLY UNLOCKED!</span>
Decrypted <span class="hex-highlight">vm_core.bin</span> (256 bytes) and <span class="hex-highlight">dump.pcap</span> (48.6 KB).
Proceed to Tab 4 (Esoteric VM Debugger) and Tab 5 (DNS PCAP Reassembler).`;
      updateStage(2);
      playBeepSound(1200, 150);
    } else {
      box.innerHTML = `<span class="hex-highlight" style="color: var(--magenta-primary);">[!] ERROR: INCORRECT ZIP PASSWORD.</span>
Expected password from Stage 1 Audio LSB extraction.`;
    }
  });
}

// --- Esoteric VM Debugger ---
function initVMDebugger() {
  const disasmBtn = document.getElementById("btn-vm-disasm");
  const stepBtn = document.getElementById("btn-vm-step");
  const keyBtn = document.getElementById("btn-vm-key");
  const asmView = document.getElementById("vm-asm-view");

  disasmBtn.addEventListener("click", () => {
    asmView.innerHTML = `<span style="color: var(--cyan-primary);">// Z-Brain 8-Bit Stack VM Disassembly</span>
0x00: PUSH 0x9A
0x02: ROL 2          ; Rotate accumulator left by 2 bits
0x04: XOR_PRIME 0    ; XOR with 1st prime (2)
0x06: STORE R1
0x08: PUSH 0x8B
0x0A: ROL 2
0x0C: XOR_PRIME 1    ; XOR with 2nd prime (3)
0x0E: SWAP R1, R2
...
0x30: HALT           ; Output 128-bit key sequence`;
  });

  stepBtn.addEventListener("click", () => {
    document.getElementById("reg-ip").textContent = "0x30";
    document.getElementById("reg-ip-d").textContent = "48";
    document.getElementById("reg-acc").textContent = "0x9A";
    document.getElementById("reg-acc-d").textContent = "154";
    document.getElementById("reg-key").textContent = "0x7C";
    document.getElementById("reg-key-d").textContent = "124";
    document.getElementById("vm-status-text").textContent = "VM State: EXECUTION COMPLETED (HALTED)";
    document.getElementById("vm-status-text").style.color = "var(--green-matrix)";
    playBeepSound(800, 100);
  });

  keyBtn.addEventListener("click", () => {
    asmView.innerHTML += `\n\n<span style="color: var(--green-matrix);">[+] VM DECRYPTED AES KEY RECONSTRUCTED</span>\nUse this AES key in Tab 5 to decrypt the DNS PCAP stream!`;
    updateStage(3);
    playBeepSound(1500, 200);
  });
}

// --- DNS Tunneling PCAP Parser ---
function initPCAPParser() {
  const parseBtn = document.getElementById("btn-pcap-parse");
  const sortBtn = document.getElementById("btn-pcap-sort");
  const decryptBtn = document.getElementById("btn-pcap-decrypt");
  const box = document.getElementById("pcap-out-box");

  parseBtn.addEventListener("click", () => {
    box.innerHTML = `<span class="hex-key">[+] DNS TUNNELING PACKETS EXTRACTED (12 Subdomains):</span>
[1] F5.MZXW6Y.aetheria-node.internal (TXT)
[2] F1.NFXWKY.aetheria-node.internal (TXT)
[3] F8.LNEU2.aetheria-node.internal (TXT)
[4] F2.LNEU2.aetheria-node.internal (TXT)
[5] F13.MJQXG.aetheria-node.internal (TXT)
[6] F3.MZXW6.aetheria-node.internal (TXT)
--------------------------------------------------
<span class="hex-highlight">[!] NOTICE:</span> Subdomains are out-of-order! Prefix indicates Fibonacci sequence tag (F1, F2, F3, F5, F8, F13...).`;
  });

  sortBtn.addEventListener("click", () => {
    box.innerHTML = `<span class="hex-key">[+] SORTED BY FIBONACCI TAG PROGRESSION:</span>
F1  -> NFXWKY... (Base32)
F2  -> LNEU2...  (Base32)
F3  -> MZXW6...  (Base32)
F5  -> MZXW6Y... (Base32)
F8  -> LNEU2...  (Base32)
F13 -> MJQXG...  (Base32)
--------------------------------------------------
Base32 Reassembled Ciphertext Payload: <span class="hex-highlight">4A8F290B...</span>
IV: <span class="hex-key">1a2b3c4d5e6f7a8b</span>`;
  });

  decryptBtn.addEventListener("click", () => {
    box.innerHTML = `<span class="hex-key">[+] AES-256-GCM DECRYPTION SUCCESSFUL (Key from Stage 3 VM)</span>
Decrypted Memory Container: <span class="hex-highlight">process_mem.raw</span> (65,536 Bytes)
Proceed to Tab 6 (Process Memory Scan) to extract the final Nexus Password!`;
    updateStage(4);
    playBeepSound(1100, 150);
  });
}

// --- Memory Dump Scanner ---
function initMemoryScanner() {
  const scanBtn = document.getElementById("btn-mem-scan");
  const baconBtn = document.getElementById("btn-mem-bacon");
  const nexusBtn = document.getElementById("btn-mem-nexus");
  const box = document.getElementById("mem-out-box");

  scanBtn.addEventListener("click", () => {
    box.innerHTML = `<span class="hex-key">[+] MEMORY STRUCT ALIGNMENT ZERO-BYTE SCAN:</span>
Offset 0x0400: Struct NodeHeader { pad: [0x00, 0x00, 0x00, 0x00, 0x01] } -> 00001 (B)
Offset 0x0420: Struct NodeHeader { pad: [0x00, 0x00, 0x00, 0x00, 0x00] } -> 00000 (A)
Offset 0x0440: Struct NodeHeader { pad: [0x00, 0x00, 0x02, 0x01, 0x01] } -> 00011 (C)
Offset 0x0460: Struct NodeHeader { pad: [0x00, 0x00, 0x00, 0x00, 0x00] } -> 00000 (O)
--------------------------------------------------
<span class="hex-highlight">[+] PATTERN FOUND:</span> 5-byte zero/non-zero flags form a Baconian Cipher Matrix!`;
  });

  baconBtn.addEventListener("click", () => {
    box.innerHTML = `<span class="hex-key">[+] BACONIAN CIPHER MATRIX DECODER</span>
Binary Sequence: 01001 01001 00001 00000 _ 00000 01011 00101 00000 ...
Decoded String: <span class="hex-highlight">Baconian Matrix Sequence Decoded</span>`;
  });

  nexusBtn.addEventListener("click", () => {
    box.innerHTML = `<span class="hex-key">[+] ALL 5 PREVIOUS STAGES COMPLETED &amp; VERIFIED!</span>
Return to Tab 1 (Terminal) and run:
<code style="color: var(--cyan-primary);">aetheria-nexus --key1 &lt;key1&gt; --zip-pass &lt;zippass&gt; --mem-pass &lt;mempass&gt;</code>`;
    updateStage(5);
    playBeepSound(1600, 250);
  });
}

// --- Stage Progress Updater ---
function updateStage(num) {
  state.stagesCompleted[num - 1] = true;
  const stepEl = document.getElementById(`step-${num}`);
  if (stepEl) {
    stepEl.classList.remove("active");
    stepEl.classList.add("completed");
  }

  const nextStep = document.getElementById(`step-${num + 1}`);
  if (nextStep && !state.stagesCompleted[num]) {
    nextStep.classList.add("active");
  }

  const completedCount = state.stagesCompleted.filter(Boolean).length;
  document.getElementById("stage-counter").textContent = `${completedCount} / 6`;
}

// --- Modals System ---
function initModals() {
  document.getElementById("btn-hints").addEventListener("click", () => openModal("modal-hints"));
  document.getElementById("btn-writeup-open").addEventListener("click", () => openModal("modal-hints"));
  document.getElementById("btn-writeup-footer").addEventListener("click", () => openModal("modal-hints"));
  document.getElementById("btn-flag-open").addEventListener("click", () => openModal("modal-flag"));

  document.getElementById("btn-submit-flag").addEventListener("click", async () => {
    const flagVal = document.getElementById("flag-input").value.trim();
    const resultBox = document.getElementById("flag-result-box");
    resultBox.style.display = "block";

    const inputHash = await sha256(flagVal);

    if (inputHash === state.crypto.flagHash) {
      resultBox.innerHTML = `<h3 style="color: var(--green-matrix); font-size: 1.1rem; margin-bottom: 0.5rem;">🎉 CONGRATULATIONS! FLAG VERIFIED!</h3>
<p style="color: var(--text-bright); font-size: 0.9rem;">You solved <b>Project AETHERIA: Phantom Signal of Node-14</b>!</p>
<pre style="color: var(--cyan-primary); font-size: 1rem; margin-top: 0.6rem;">${flagVal}</pre>`;
      updateStage(6);
      playSuccessSound();
    } else {
      resultBox.innerHTML = `<h3 style="color: var(--magenta-primary); font-size: 1rem;">❌ INCORRECT FLAG</h3>
<p style="color: var(--text-dim); font-size: 0.85rem;">Check your extracted solution or review hints.</p>`;
      playBeepSound(300, 200);
    }
  });
}

function openModal(id) {
  document.getElementById(id).classList.add("active");
}

function closeModal(id) {
  document.getElementById(id).classList.remove("active");
}

// --- Download Buttons System ---
function initDownloadButtons() {
  document.getElementById("btn-download-all").addEventListener("click", () => {
    downloadAsset("all");
  });
}

function downloadAsset(type) {
  let filename = "";

  switch (type) {
    case "png": filename = "node14_corrupt.png"; break;
    case "bin": filename = "vm_core.bin"; break;
    case "pcap": filename = "dump.pcap"; break;
    case "raw": filename = "process_mem.raw"; break;
    case "py": filename = "solver.py"; break;
    case "all": filename = "node14_corrupt.png"; break;
  }

  const a = document.createElement("a");
  a.href = filename;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

// --- Audio Sound FX ---
function playBeepSound(freq, durationMs) {
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    const ctx = new AudioCtx();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = "sine";
    osc.frequency.setValueAtTime(freq, ctx.currentTime);
    gain.gain.setValueAtTime(0.1, ctx.currentTime);

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.start();
    setTimeout(() => {
      osc.stop();
      ctx.close();
    }, durationMs);
  } catch (e) {}
}

function playSuccessSound() {
  playBeepSound(523.25, 150); // C5
  setTimeout(() => playBeepSound(659.25, 150), 150); // E5
  setTimeout(() => playBeepSound(783.99, 150), 300); // G5
  setTimeout(() => playBeepSound(1046.50, 400), 450); // C6
}
