// Minimal client wiring for WebRTC + Realtime (offer→/api/sdp→answer)
let pc=null, dc=null, audioEl=null, localStream=null;
let micSender=null, micTrack=null, stopVAD=null;
let csrfToken=null, tokenData=null;
let languageOk=true;
let userBubble=null, aiBubble=null;
const CONNECT_DEADLINE_MS = 50_000;
const DEFAULT_VOICE = 'marin';

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
function appendTranscript(role, text){
  const t=document.getElementById('transcript');
  let bubble = role==='AI'?aiBubble:userBubble;
  if(!bubble){
    bubble=document.createElement('div');
    bubble.className=role==='AI'?'ai-message':'customer-message';
    bubble.innerHTML=`<div class="message-header"><strong>${role}</strong><span>${new Date().toLocaleTimeString('ja-JP')}</span></div><div class="message-text"></div>`;
    t.appendChild(bubble);
    if(role==='AI') aiBubble=bubble; else userBubble=bubble;
  }
  bubble.querySelector('.message-text').textContent += text;
  t.scrollTop=t.scrollHeight;
}
function finalizeTranscript(role){
  if(role==='AI') aiBubble=null; else userBubble=null;
}

function setupVAD(stream, sender, track){
  const ctx = new (window.AudioContext||window.webkitAudioContext)();
  const src = ctx.createMediaStreamSource(stream);
  const analyser = ctx.createAnalyser();
  analyser.fftSize = 2048;
  src.connect(analyser);
  const data = new Uint8Array(analyser.fftSize);
  let silentSince = Date.now();
  let silenced = false;
  let rafId;
  const SILENCE_MS = 1000;
  const THRESH = 0.01;

  function check(){
    analyser.getByteTimeDomainData(data);
    let sum=0;
    for(let i=0;i<data.length;i++){ const v=(data[i]-128)/128; sum+=v*v; }
    const rms = Math.sqrt(sum/data.length);
    if(rms < THRESH){
      if(!silenced && Date.now()-silentSince > SILENCE_MS){
        sender.replaceTrack(null);
        silenced=true;
      }
    }else{
      silentSince = Date.now();
      if(silenced){
        sender.replaceTrack(track);
        silenced=false;
      }
    }
    rafId = requestAnimationFrame(check);
  }
  check();
  return ()=>{ cancelAnimationFrame(rafId); src.disconnect(); analyser.disconnect(); ctx.close(); };
}
async function startCall(){
  const consent=document.getElementById('consent-checkbox'); if(!consent?.checked){ alert('同意にチェックしてください'); return; }
  try{
    updateStatus('接続中...');
    tokenData = await getToken(DEFAULT_VOICE);
    const { token, ice_servers } = tokenData;

    pc = new RTCPeerConnection({ iceServers: ice_servers||[], iceCandidatePoolSize: 10 });
    pc.addTransceiver('audio',{direction:'recvonly'});
    audioEl = document.createElement('audio'); audioEl.autoplay = true; audioEl.playsInline = true;
    pc.ontrack = (e)=>{ if(e.track.kind==='audio'){ audioEl.srcObject=e.streams[0]; audioEl.play().catch(()=>{});} };

    // mic
    try{
      localStream = await navigator.mediaDevices.getUserMedia({ audio:{ echoCancellation:true, noiseSuppression:true, autoGainControl:true, sampleRate:48000 } });
      micTrack = localStream.getAudioTracks()[0];
      micSender = pc.addTrack(micTrack, localStream);
      stopVAD = setupVAD(localStream, micSender, micTrack);
    }catch(e){ throw new Error('マイクエラー: '+e.message); }

    dc = pc.createDataChannel('oai-events',{ ordered:true, maxRetransmits:3 });
    dc.onopen = ()=>{
      dc.send(JSON.stringify({
        type:'response.create',
        response:{
          modalities:['audio','text'],
          instructions:'アシスタントです。ご用件をお話しください。',
        }
      }));
    };
    dc.onmessage = (ev)=>{
      try{
        const data = JSON.parse(ev.data);
        if(data.type==='input_audio_transcript.delta'){
          if(languageOk && data.language && data.language!=='ja'){
            languageOk=false;
            dc.send(JSON.stringify({
              type:'response.create',
              response:{
                modalities:['audio','text'],
                instructions:'申し訳ありませんが、日本語のみ対応しています。',
              }
            }));
            dc.send(JSON.stringify({type:'conversation.end'}));
          }
          if(data.delta) appendTranscript('お客様', data.delta);
        }
        if(data.type==='input_audio_transcript.done'){ finalizeTranscript('お客様'); }
        if(data.type==='response.text.delta' && data.delta){ appendTranscript('AI', data.delta); }
        if(data.type==='response.text.done'){ finalizeTranscript('AI'); }
      }catch{}
    };

    const connectTimer = setTimeout(()=>{ if(pc && !['connected','completed'].includes(pc.iceConnectionState)){ updateStatus('接続タイムアウト'); endCall(); } }, CONNECT_DEADLINE_MS);

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await getCsrfToken(); // refresh CSRF token (rotated after /api/token)
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
  if(stopVAD){ try{stopVAD();}catch{} stopVAD=null; }
  micSender=null; micTrack=null;
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
