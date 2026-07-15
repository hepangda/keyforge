export const LOGIN_BROWSER_SCRIPT = `
(function(){
  const button=document.querySelector("[data-passkey-login]");
  if(!button||!window.PublicKeyCredential){if(button)button.hidden=true;return}
  const status=document.querySelector("[data-passkey-status]");
  const decode=(value)=>{const base=value.replace(/-/g,"+").replace(/_/g,"/");const raw=atob(base+"=".repeat((4-base.length%4)%4));return Uint8Array.from(raw,c=>c.charCodeAt(0)).buffer};
  const encode=(value)=>{const bytes=new Uint8Array(value);let raw="";for(const byte of bytes)raw+=String.fromCharCode(byte);return btoa(raw).split("+").join("-").split("/").join("_").replace(/=+$/g,"")};
  const message=(value)=>{if(status){status.textContent=value;status.hidden=value===""}};
  button.addEventListener("click",async()=>{
    button.disabled=true;message(button.dataset.waitingMessage||"");
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
    }catch(error){if(error&&error.name==="NotAllowedError")message(button.dataset.cancelledMessage||"");else message(button.dataset.errorMessage||"");button.disabled=false}
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
  const redirectForReauthentication=async(response)=>{if(response.status!==403)return false;try{const body=await response.clone().json();if(body.error==="recent_authentication_required"){window.location.assign(body.reauthenticate_url||"/login?reauth=1&return_to=%2F%3Fsection%3Dlogin-methods");return true}}catch(error){}return false};
  button.addEventListener("click",async()=>{
    button.disabled=true;message(button.dataset.waitingMessage||"");
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
      window.location.assign("/?section=login-methods&notice=passkey_added");
    }catch(error){if(error&&error.name==="NotAllowedError")message(button.dataset.cancelledMessage||"");else message(button.dataset.errorMessage||"");button.disabled=false}
  });
})();`

export const FORMS_BROWSER_SCRIPT = `
(function(){
  var setLanguageReturnTo=function(form){
    var returnTo=form.querySelector('[name="return_to"]');
    if(returnTo)returnTo.value=window.location.pathname+window.location.search+window.location.hash;
  };
  document.addEventListener("change",function(event){
    var select=event.target;
    if(!(select&&select.matches&&select.matches('[data-language-picker] select[name="language"]')))return;
    var form=select.form;if(!form)return;
    if(typeof form.requestSubmit==="function")form.requestSubmit();
    else{setLanguageReturnTo(form);form.submit()}
  });
  document.addEventListener("submit",function(event){
    var form=event.target;
    if(!(form&&form.tagName==="FORM"))return;
    if(form.matches("[data-language-picker]"))setLanguageReturnTo(form);
    if(form.dataset.busy){event.preventDefault();return}
    form.dataset.busy="1";
    var button=event.submitter||form.querySelector("button[type=submit],button:not([type])");
    if(button){button.classList.add("is-loading");button.setAttribute("aria-busy","true")}
  },true);
})();`

export const CONSOLE_BROWSER_SCRIPT = `
(function(){
  document.querySelectorAll("[data-console-wizard]").forEach(function(form){
    var panels=Array.from(form.querySelectorAll("[data-wizard-step]"));
    var markers=Array.from(form.querySelectorAll("[data-wizard-marker]"));
    var next=form.querySelector("[data-wizard-next]");
    var back=form.querySelector("[data-wizard-back]");
    var submit=form.querySelector("[data-wizard-submit]");
    if(!panels.length||!next||!back||!submit)return;
    var current=0;
    var labels={application:form.dataset.labelApplication||"",device:form.dataset.labelDevice||"",service:form.dataset.labelService||"",public:form.dataset.labelPublic||"",confidential:form.dataset.labelConfidential||""};
    var valueFor=function(name){
      var fields=Array.from(form.querySelectorAll('[name="'+name+'"]'));
      if(!fields.length)return "—";
      if(fields[0].type==="checkbox"){
        var values=fields.filter(function(field){return field.checked}).map(function(field){return (field.value||"").trim()}).filter(Boolean);
        return values.join("\\n")||"—";
      }
      var checked=form.querySelector('[name="'+name+'"]:checked');
      var field=checked||fields[0];
      if(!field)return "—";
      var value=(field.value||"").trim();
      return labels[value]||value||"—";
    };
    var updateReview=function(){
      form.querySelectorAll("[data-review-for]").forEach(function(target){target.textContent=valueFor(target.dataset.reviewFor)});
    };
    var resourceInputs=Array.from(form.querySelectorAll('[name="allowed_resources"][type="checkbox"]'));
    var redirect=form.querySelector('[name="redirect_uris"]');
    var logoutRedirect=form.querySelector('[name="post_logout_redirect_uris"]');
    var grants=form.querySelector('[name="allowed_grant_types"]');
    var scopes=form.querySelector('[name="allowed_scopes"]');
    var defaultResource=form.querySelector('[name="default_resource"]');
    var syncResourceRequirement=function(){
      var selected=resourceInputs.some(function(input){return input.checked});
      resourceInputs.forEach(function(input,index){input.required=!selected&&index===0});
    };
    var syncDefaultResource=function(){
      if(!defaultResource)return;
      var selected=resourceInputs.filter(function(input){return input.checked});
      if(!selected.some(function(input){return input.value===defaultResource.value}))defaultResource.value=selected[0]?selected[0].value:"";
    };
    var syncKindRequirements=function(kind){if(redirect)redirect.required=kind==="application"};
    var suggestResource=function(requiredScopes){
      var candidate=resourceInputs.find(function(input){
        var offered=(input.dataset.resourceScopes||"").split(/\\s+/).filter(Boolean);
        return requiredScopes.every(function(scope){return offered.includes(scope)});
      });
      if(!candidate)return;
      resourceInputs.forEach(function(input){input.checked=input===candidate});
      if(defaultResource)defaultResource.value=candidate.value;
    };
    var setKindDefaults=function(kind){
      var typeValue=kind==="service"?"confidential":"public";
      var typeInput=form.querySelector('[name="type"][value="'+typeValue+'"]');if(typeInput)typeInput.checked=true;
      var nextScopes=kind==="service"?["api.read"]:["openid","profile","email","offline_access"];
      if(grants)grants.value=kind==="service"?"client_credentials":kind==="device"?"urn:ietf:params:oauth:grant-type:device_code\\nrefresh_token":"authorization_code\\nrefresh_token";
      if(scopes)scopes.value=nextScopes.join("\\n");
      if(kind!=="application"){if(redirect)redirect.value="";if(logoutRedirect)logoutRedirect.value=""}
      syncKindRequirements(kind);suggestResource(nextScopes);syncResourceRequirement();updateReview();
    };
    var show=function(index){
      current=Math.max(0,Math.min(index,panels.length-1));
      panels.forEach(function(panel,i){panel.classList.toggle("wizard-panel--active",i===current)});
      markers.forEach(function(marker,i){marker.classList.toggle("wizard-step--active",i===current);marker.classList.toggle("wizard-step--done",i<current)});
      back.hidden=current===0;next.hidden=current===panels.length-1;submit.hidden=current!==panels.length-1;
      if(current===panels.length-1)updateReview();
    };
    var validCurrent=function(){
      var fields=Array.from(panels[current].querySelectorAll("input,select,textarea"));
      for(var i=0;i<fields.length;i++){if(!fields[i].checkValidity()){fields[i].reportValidity();return false}}
      return true;
    };
    next.addEventListener("click",function(){if(validCurrent())show(current+1)});
    back.addEventListener("click",function(){show(current-1)});
    form.addEventListener("input",updateReview);
    form.addEventListener("change",function(event){
      var field=event.target;
      if(field&&field.name==="client_kind")setKindDefaults(field.value);
      syncResourceRequirement();syncDefaultResource();updateReview();
    });
    var selectedKind=form.querySelector('[name="client_kind"]:checked');
    syncKindRequirements(selectedKind?selectedKind.value:"application");syncResourceRequirement();
    form.dataset.wizardReady="1";show(0);updateReview();
  });
})();`
