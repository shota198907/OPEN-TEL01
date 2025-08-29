// Minimal client wiring for WebRTC + Realtime (offer→/api/sdp→answer)
let pc=null, dc=null, audioEl=null, localStream=null;
let csrfToken=null, tokenData=null;
const CONNECT_DEADLINE_MS = 50_000;

function log(level, msg, data={}){ console[level]({t:new Date().toISOString(), msg, ...data}); }

async function getCsrfToken(){
  const r = await fetch('/api/csrf-token', { credentials:'include' });
  const j = await r.json(); csrfToken=j.csrfToken; return csrfToken;
}
async function getToken(voice, model){
  if(!csrfToken) await getCsrfToken();
  const r = await fetch('/api/token', {
    method:'POST',
    headers:{ 'Content-Type':'application/json', 'X-CSRF-Token': csrfToken },
    credentials:'include',
    body: JSON.stringify({ voice, model })
  });
  if(!r.ok){ const e=await r.json().catch(()=>({})); throw new Error(e.error||'token failed'); }
  return r.json();
}

function updateStatus(s){ const el=document.getElementById('status'); if(el) el.textContent=`状態: ${s}`; }
function updateTranscript(role, text){ const t=document.getElementById('transcript'); const d=document.createElement('div'); d.className=role==='AI'?'ai-message':'customer-message'; d.innerHTML=`<div class="message-header"><strong>${role}</strong><span>${new Date().toLocaleTimeString('ja-JP')}</span></div><div class="message-text">${text}</div>`; t.appendChild(d); t.scrollTop=t.scrollHeight; }

async function startCall(){
  const consent=document.getElementById('consent-checkbox'); if(!consent?.checked){ alert('同意にチェックしてください'); return; }
  try{
    updateStatus('接続中...');
    tokenData = await getToken();
    const { token, ice_servers } = tokenData;

    pc = new RTCPeerConnection({ iceServers: ice_servers||[], iceCandidatePoolSize: 10 });
    pc.addTransceiver('audio',{direction:'recvonly'});
    audioEl = document.createElement('audio'); audioEl.autoplay = true; audioEl.playsInline = true;
    pc.ontrack = (e)=>{ if(e.track.kind==='audio'){ audioEl.srcObject=e.streams[0]; audioEl.play().catch(()=>{});} };

    // mic
    try{
      localStream = await navigator.mediaDevices.getUserMedia({ audio:{ echoCancellation:true, noiseSuppression:true, autoGainControl:true, sampleRate:48000 } });
      localStream.getAudioTracks().forEach(tr=>pc.addTrack(tr, localStream));
    }catch(e){ throw new Error('マイクエラー: '+e.message); }

    dc = pc.createDataChannel('oai-events',{ ordered:true, maxRetransmits:3 });
    dc.onmessage = (ev)=>{
      try{
        const data = JSON.parse(ev.data);
        if(data.type==='response.audio_transcript.delta'){ updateTranscript('AI', data.delta); }
        if(data.type==='response.audio_transcript.done'){ /* no-op (already appended) */ }
      }catch{}
    };

    const connectTimer = setTimeout(()=>{ if(pc && !['connected','completed'].includes(pc.iceConnectionState)){ updateStatus('接続タイムアウト'); endCall(); } }, CONNECT_DEADLINE_MS);

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    const sdpRes = await fetch('/api/sdp', {
      method:'POST',
      headers:{ 'Authorization':`Bearer ${token}`, 'Content-Type':'application/sdp', 'X-CSRF-Token': csrfToken||'' },
      body: offer.sdp,
      credentials:'include'
    });
    if(!sdpRes.ok){ const txt=await sdpRes.text(); throw new Error('SDP失敗: '+sdpRes.status+' '+txt.slice(0,120)); }
    const answerSdp = await sdpRes.text();
    await pc.setRemoteDescription({ type:'answer', sdp: answerSdp });
    clearTimeout(connectTimer);
    updateStatus('通話中');
  }catch(e){
    updateStatus('エラー: '+e.message);
    endCall();
  }
}

function endCall(){
  if(dc){ try{dc.close();}catch{} dc=null; }
  if(pc){ try{pc.close();}catch{} pc=null; }
  if(localStream){ localStream.getTracks().forEach(t=>t.stop()); localStream=null; }
  updateStatus('待機中');
}

document.addEventListener('DOMContentLoaded', ()=>{
  document.getElementById('callBtn')?.addEventListener('click', ()=>{
    if(!pc) startCall(); else if(confirm('通話を終了しますか？')) endCall();
  });
  document.getElementById('clearTranscript')?.addEventListener('click', ()=>{
    const t=document.getElementById('transcript'); t.innerHTML='';
  });
});
