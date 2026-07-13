export const LOGIN_BROWSER_SCRIPT = `
(function(){
  const button=document.querySelector("[data-passkey-login]");
  if(!button||!window.PublicKeyCredential){if(button)button.hidden=true;return}
  const status=document.querySelector("[data-passkey-status]");
  const decode=(value)=>{const base=value.replace(/-/g,"+").replace(/_/g,"/");const raw=atob(base+"=".repeat((4-base.length%4)%4));return Uint8Array.from(raw,c=>c.charCodeAt(0)).buffer};
  const encode=(value)=>{const bytes=new Uint8Array(value);let raw="";for(const byte of bytes)raw+=String.fromCharCode(byte);return btoa(raw).split("+").join("-").split("/").join("_").replace(/=+$/g,"")};
  const message=(value)=>{if(status){status.textContent=value;status.hidden=value===""}};
  button.addEventListener("click",async()=>{
    button.disabled=true;message("Waiting for your passkey…");
    try{
      const optionsResponse=await fetch("/webauthn/login/options",{method:"POST",headers:{accept:"application/json"}});
      if(!optionsResponse.ok)throw new Error("options");
      const options=await optionsResponse.json();
      options.challenge=decode(options.challenge);
      if(options.allowCredentials)options.allowCredentials=options.allowCredentials.map(item=>({...item,id:decode(item.id)}));
      const credential=await navigator.credentials.get({publicKey:options});
      if(!credential)throw new Error("cancelled");
      const response={id:credential.id,rawId:encode(credential.rawId),type:credential.type,authenticatorAttachment:credential.authenticatorAttachment,clientExtensionResults:credential.getClientExtensionResults(),returnTo:button.dataset.returnTo||"/",reauthenticate:button.dataset.reauth==="1",response:{clientDataJSON:encode(credential.response.clientDataJSON),authenticatorData:encode(credential.response.authenticatorData),signature:encode(credential.response.signature),userHandle:credential.response.userHandle?encode(credential.response.userHandle):null}};
      const verified=await fetch("/webauthn/login/verify",{method:"POST",headers:{"content-type":"application/json",accept:"application/json"},body:JSON.stringify(response)});
      if(!verified.ok)throw new Error("verify");
      const body=await verified.json();if(!body.verified)throw new Error("verify");
      window.location.assign(body.redirect_to||button.dataset.returnTo||"/");
    }catch(error){if(error&&error.name==="NotAllowedError")message("Passkey sign-in was cancelled.");else message("Passkey sign-in could not be completed.");button.disabled=false}
  });
})();`

export const ACCOUNT_BROWSER_SCRIPT = `
(function(){
  const button=document.querySelector("[data-passkey-register]");
  if(!button||!window.PublicKeyCredential){if(button)button.hidden=true;return}
  const status=document.querySelector("[data-passkey-status]");
  const decode=(value)=>{const base=value.replace(/-/g,"+").replace(/_/g,"/");const raw=atob(base+"=".repeat((4-base.length%4)%4));return Uint8Array.from(raw,c=>c.charCodeAt(0)).buffer};
  const encode=(value)=>{const bytes=new Uint8Array(value);let raw="";for(const byte of bytes)raw+=String.fromCharCode(byte);return btoa(raw).split("+").join("-").split("/").join("_").replace(/=+$/g,"")};
  const message=(value)=>{if(status){status.textContent=value;status.hidden=value===""}};
  const redirectForReauthentication=async(response)=>{if(response.status!==403)return false;try{const body=await response.clone().json();if(body.error==="recent_authentication_required"){window.location.assign(body.reauthenticate_url||"/login?reauth=1&return_to=%2F%3Fsection%3Dpasskeys");return true}}catch(error){}return false};
  button.addEventListener("click",async()=>{
    button.disabled=true;message("Follow your browser's passkey prompt…");
    try{
      const csrf=button.dataset.csrf||"";
      const optionsResponse=await fetch("/webauthn/register/options",{method:"POST",headers:{accept:"application/json","x-keyforge-csrf":csrf}});
      if(!optionsResponse.ok){if(await redirectForReauthentication(optionsResponse))return;throw new Error("options")}
      const options=await optionsResponse.json();options.challenge=decode(options.challenge);options.user.id=decode(options.user.id);
      if(options.excludeCredentials)options.excludeCredentials=options.excludeCredentials.map(item=>({...item,id:decode(item.id)}));
      const credential=await navigator.credentials.create({publicKey:options});if(!credential)throw new Error("cancelled");
      const transports=typeof credential.response.getTransports==="function"?credential.response.getTransports():[];
      const response={id:credential.id,rawId:encode(credential.rawId),type:credential.type,authenticatorAttachment:credential.authenticatorAttachment,clientExtensionResults:credential.getClientExtensionResults(),response:{clientDataJSON:encode(credential.response.clientDataJSON),attestationObject:encode(credential.response.attestationObject),transports}};
      const verified=await fetch("/webauthn/register/verify",{method:"POST",headers:{"content-type":"application/json",accept:"application/json","x-keyforge-csrf":csrf},body:JSON.stringify(response)});
      if(!verified.ok){if(await redirectForReauthentication(verified))return;throw new Error("verify")}const body=await verified.json();if(!body.verified)throw new Error("verify");
      window.location.assign("/?section=passkeys&notice=passkey_added");
    }catch(error){if(error&&error.name==="NotAllowedError")message("Passkey creation was cancelled.");else message("Passkey creation could not be completed.");button.disabled=false}
  });
})();`

export const FORMS_BROWSER_SCRIPT = `
(function(){
  document.addEventListener("submit",function(event){
    var form=event.target;
    if(!(form&&form.tagName==="FORM"))return;
    if(form.dataset.busy){event.preventDefault();return}
    form.dataset.busy="1";
    var button=event.submitter||form.querySelector("button[type=submit],button:not([type])");
    if(button){button.classList.add("is-loading");button.setAttribute("aria-busy","true")}
  },true);
})();`
