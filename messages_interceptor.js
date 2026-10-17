(async () => {
  window.muestrasPQC = [];
  const TOTAL = 100;

  const originalFetch = window.fetch;
  window.fetch = async function(...args) {
    const [url, config] = args;
    if (config && config.body) {
      try {
        const payload = JSON.parse(config.body);
        const ciphertextReal = payload.ciphertext || payload.ciphertext_b64 || payload.kem_payload;
        
        if (ciphertextReal && window.muestrasPQC.length < TOTAL) {
          window.muestrasPQC.push(ciphertextReal);
          console.log(`[${window.muestrasPQC.length}/${TOTAL}] Successfully captured.`);
          
          if (window.muestrasPQC.length === TOTAL) {
              console.log("100 samples completed. Run downloadSamples() to export the TXT file.");
          }
        }
      } catch(e) {}
    }
    return originalFetch.apply(this, args);
  };

    window.downloadSamples = () => {
    const blob = new Blob([window.muestrasPQC.join('\n')], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'pqc_messages.txt';
    a.click();
  };

    console.log("Interceptor active. Send 100 messages manually in the chat, then execute downloadSamples() in the console.");
})();