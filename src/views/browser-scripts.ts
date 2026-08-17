export const LOGIN_BROWSER_SCRIPT = `
(function(){
  const button=document.querySelector("[data-passkey-login]");
  if(!button||!window.PublicKeyCredential){if(button)button.hidden=true;return}
  button.hidden=false;
  const status=document.querySelector("[data-passkey-status]");
  const decode=(value)=>{const base=value.replace(/-/g,"+").replace(/_/g,"/");const raw=atob(base+"=".repeat((4-base.length%4)%4));return Uint8Array.from(raw,c=>c.charCodeAt(0)).buffer};
  const encode=(value)=>{const bytes=new Uint8Array(value);let raw="";for(const byte of bytes)raw+=String.fromCharCode(byte);return btoa(raw).split("+").join("-").split("/").join("_").replace(/=+$/g,"")};
  const message=(value)=>{if(status){status.textContent=value;status.hidden=value===""}};
  button.addEventListener("click",async()=>{
    button.disabled=true;message(button.dataset.waitingMessage||"");
    try{
      const optionsResponse=await fetch("/webauthn/login/options",{method:"POST",headers:{accept:"application/json"}});
      if(!optionsResponse.ok){if(optionsResponse.status===429){message(button.dataset.rateLimitedMessage||"");button.disabled=false;return}throw new Error("options")}
      const options=await optionsResponse.json();
      options.challenge=decode(options.challenge);
      if(options.allowCredentials)options.allowCredentials=options.allowCredentials.map(item=>({...item,id:decode(item.id)}));
      const credential=await navigator.credentials.get({publicKey:options});
      if(!credential)throw new Error("cancelled");
      const response={id:credential.id,rawId:encode(credential.rawId),type:credential.type,authenticatorAttachment:credential.authenticatorAttachment,clientExtensionResults:credential.getClientExtensionResults(),returnTo:button.dataset.returnTo||"/",reauthenticate:button.dataset.reauth==="1",response:{clientDataJSON:encode(credential.response.clientDataJSON),authenticatorData:encode(credential.response.authenticatorData),signature:encode(credential.response.signature),userHandle:credential.response.userHandle?encode(credential.response.userHandle):null}};
      const verified=await fetch("/webauthn/login/verify",{method:"POST",headers:{"content-type":"application/json",accept:"application/json"},body:JSON.stringify(response)});
      if(!verified.ok){if(verified.status===429){message(button.dataset.rateLimitedMessage||"");button.disabled=false;return}throw new Error("verify")}
      const body=await verified.json();if(!body.verified)throw new Error("verify");
      window.location.assign(body.redirect_to||button.dataset.returnTo||"/");
    }catch(error){if(error&&error.name==="NotAllowedError")message(button.dataset.cancelledMessage||"");else if(error instanceof TypeError)message(button.dataset.networkErrorMessage||button.dataset.errorMessage||"");else message(button.dataset.errorMessage||"");button.disabled=false}
  });
})();`

export const ACCOUNT_BROWSER_SCRIPT = `
(function(){
  const button=document.querySelector("[data-passkey-register]");
  if(!button||!window.PublicKeyCredential){if(button)button.hidden=true;return}
  button.hidden=false;
  const status=document.querySelector("[data-passkey-status]");
  const decode=(value)=>{const base=value.replace(/-/g,"+").replace(/_/g,"/");const raw=atob(base+"=".repeat((4-base.length%4)%4));return Uint8Array.from(raw,c=>c.charCodeAt(0)).buffer};
  const encode=(value)=>{const bytes=new Uint8Array(value);let raw="";for(const byte of bytes)raw+=String.fromCharCode(byte);return btoa(raw).split("+").join("-").split("/").join("_").replace(/=+$/g,"")};
  const message=(value)=>{if(status){status.textContent=value;status.hidden=value===""}};
  const redirectForReauthentication=async(response)=>{if(response.status!==403)return false;try{const body=await response.clone().json();if(body.error==="recent_authentication_required"){window.location.assign(body.reauthenticate_url||"/login?reauth=1&return_to=%2F");return true}}catch(error){}return false};
  button.addEventListener("click",async()=>{
    button.disabled=true;message(button.dataset.waitingMessage||"");
    try{
      const csrf=button.dataset.csrf||"";
      const returnTo=button.dataset.returnTo||"/";
      const optionsResponse=await fetch("/webauthn/register/options",{method:"POST",headers:{accept:"application/json","x-keyforge-csrf":csrf,"x-keyforge-return-to":returnTo}});
      if(!optionsResponse.ok){if(await redirectForReauthentication(optionsResponse))return;if(optionsResponse.status===429){message(button.dataset.rateLimitedMessage||"");button.disabled=false;return}throw new Error("options")}
      const options=await optionsResponse.json();options.challenge=decode(options.challenge);options.user.id=decode(options.user.id);
      if(options.excludeCredentials)options.excludeCredentials=options.excludeCredentials.map(item=>({...item,id:decode(item.id)}));
      const credential=await navigator.credentials.create({publicKey:options});if(!credential)throw new Error("cancelled");
      const transports=typeof credential.response.getTransports==="function"?credential.response.getTransports():[];
      const response={id:credential.id,rawId:encode(credential.rawId),type:credential.type,authenticatorAttachment:credential.authenticatorAttachment,clientExtensionResults:credential.getClientExtensionResults(),response:{clientDataJSON:encode(credential.response.clientDataJSON),attestationObject:encode(credential.response.attestationObject),transports}};
      const verified=await fetch("/webauthn/register/verify",{method:"POST",headers:{"content-type":"application/json",accept:"application/json","x-keyforge-csrf":csrf,"x-keyforge-return-to":returnTo},body:JSON.stringify(response)});
      if(!verified.ok){if(await redirectForReauthentication(verified))return;if(verified.status===429){message(button.dataset.rateLimitedMessage||"");button.disabled=false;return}throw new Error("verify")}const body=await verified.json();if(!body.verified)throw new Error("verify");
      window.location.assign("/?section=login-methods&notice=passkey_added");
    }catch(error){if(error&&error.name==="NotAllowedError")message(button.dataset.cancelledMessage||"");else if(error instanceof TypeError)message(button.dataset.networkErrorMessage||button.dataset.errorMessage||"");else message(button.dataset.errorMessage||"");button.disabled=false}
  });
})();`

/**
 * In-page avatar uploader with a selection-rectangle cropper.
 *
 * The whole photo stays visible and the user drags a square selection over the
 * part they want, the way every familiar cropping tool works. The alternative —
 * a fixed viewport the image is panned behind — hides most of the picture and
 * inverts the direction of every gesture.
 *
 * Rendering the selection through a canvas is also what makes the size limit a
 * non-issue (a multi-megabyte camera photo leaves as a few hundred KB) and what
 * strips EXIF and any bytes appended after the image data, since the server
 * cannot re-encode.
 *
 * Everything degrades: without JavaScript the form posts normally and the
 * server answers with a redirect and a notice; if canvas rendering is
 * unavailable the original file is uploaded and the server's limits still
 * apply.
 */
export const AVATAR_BROWSER_SCRIPT = `
(function(){
  var form=document.querySelector("[data-avatar-form]");
  if(!form||!window.FormData||!window.fetch)return;
  var input=form.querySelector('input[type="file"][name="avatar"]');
  var preview=form.querySelector("[data-avatar-preview]");
  var status=form.querySelector("[data-avatar-status]");
  var submit=form.querySelector("[data-avatar-submit]");
  var cropper=form.querySelector("[data-avatar-cropper]");
  var canvas=form.querySelector("[data-avatar-canvas]");
  var cancel=form.querySelector("[data-avatar-cancel]");
  var reset=form.querySelector("[data-avatar-reset]");
  var removeForm=document.querySelector("[data-avatar-remove]");
  if(!input||!submit)return;
  var maxBytes=parseInt(form.dataset.maxBytes||"0",10)||0;
  var dimension=parseInt(form.dataset.dimension||"512",10)||512;
  var text=function(key){return form.dataset[key]||""};
  var objectUrl=null;
  var busy=false;
  // These only make sense while a selection is open. They ship visible so a
  // no-JavaScript form is unaffected, and are hidden here on enhancement.
  if(cancel)cancel.hidden=true;
  if(reset)reset.hidden=true;

  var message=function(value,kind){
    if(!status)return;
    status.textContent=value;
    status.hidden=value==="";
    status.className="inline-status"+(kind?" inline-status--"+kind:"");
  };
  var setBusy=function(value){
    busy=value;
    submit.disabled=value;
    submit.classList.toggle("is-loading",value);
    if(value)submit.setAttribute("aria-busy","true");else submit.removeAttribute("aria-busy");
  };
  var showPreview=function(source){
    if(!preview)return;
    if(preview.tagName!=="IMG"){
      var image=document.createElement("img");
      image.className=preview.className.replace("avatar--fallback","").trim();
      image.alt="";
      if(preview.parentNode)preview.parentNode.replaceChild(image,preview);
      preview=image;
    }
    if(typeof source==="string"){
      if(objectUrl){URL.revokeObjectURL(objectUrl);objectUrl=null}
      preview.src=source;
      return;
    }
    if(objectUrl)URL.revokeObjectURL(objectUrl);
    objectUrl=URL.createObjectURL(source);
    preview.src=objectUrl;
  };

  var crop=null;
  var canvasReady=!!(canvas&&typeof canvas.getContext==="function"&&canvas.getContext("2d")&&typeof canvas.toBlob==="function");
  var HANDLE=9;
  var MIN_SIDE=40;
  var MAX_CANVAS=340;
  var MIN_VIEW_SIDE=120;

  // A panorama or a tiny image can have a viewport shorter than MIN_SIDE, so
  // the floor must never exceed what the image can actually contain.
  var minSide=function(){
    return Math.min(MIN_SIDE,Math.min(crop.viewW,crop.viewH));
  };
  var clampSelection=function(){
    if(!crop)return;
    var limit=Math.min(crop.viewW,crop.viewH);
    crop.size=Math.min(limit,Math.max(minSide(),crop.size));
    crop.x=Math.max(0,Math.min(crop.viewW-crop.size,crop.x));
    crop.y=Math.max(0,Math.min(crop.viewH-crop.size,crop.y));
  };
  var draw=function(){
    if(!crop||!canvas)return;
    var context=canvas.getContext("2d");
    if(!context)return;
    context.clearRect(0,0,crop.viewW,crop.viewH);
    context.drawImage(crop.image,0,0,crop.viewW,crop.viewH);
    // Dim everything outside the selection so the chosen square reads clearly.
    context.save();
    context.fillStyle="rgba(8,9,13,.58)";
    context.beginPath();
    context.rect(0,0,crop.viewW,crop.viewH);
    context.rect(crop.x,crop.y,crop.size,crop.size);
    context.fill("evenodd");
    context.restore();
    // The avatar is rendered as a circle everywhere else, so show that framing.
    context.save();
    context.strokeStyle="rgba(255,255,255,.85)";
    context.lineWidth=2;
    context.strokeRect(crop.x+1,crop.y+1,crop.size-2,crop.size-2);
    context.globalAlpha=.55;
    context.beginPath();
    context.arc(crop.x+crop.size/2,crop.y+crop.size/2,crop.size/2-1,0,Math.PI*2);
    context.stroke();
    context.restore();
    context.fillStyle="#ffffff";
    corners().forEach(function(corner){
      context.fillRect(corner[0]-HANDLE/2,corner[1]-HANDLE/2,HANDLE,HANDLE);
    });
  };
  var corners=function(){
    return [
      [crop.x,crop.y],
      [crop.x+crop.size,crop.y],
      [crop.x,crop.y+crop.size],
      [crop.x+crop.size,crop.y+crop.size],
    ];
  };
  var resetSelection=function(){
    if(!crop)return;
    crop.size=Math.min(crop.viewW,crop.viewH);
    crop.x=(crop.viewW-crop.size)/2;
    crop.y=(crop.viewH-crop.size)/2;
    clampSelection();draw();
  };
  var openCropper=function(image){
    // Size the canvas to the photo's aspect ratio so the whole picture is
    // visible with no letterboxing, and selection coordinates map 1:1 to it.
    var longest=Math.max(image.naturalWidth,image.naturalHeight)||1;
    var shortest=Math.max(1,Math.min(image.naturalWidth,image.naturalHeight));
    // Fit the long edge, but keep an extreme panorama from collapsing into an
    // unusable sliver — the long edge may grow rather than leave the short one
    // a few pixels tall.
    var viewScale=Math.max(MAX_CANVAS/longest,Math.min(MIN_VIEW_SIDE/shortest,MAX_CANVAS*3/longest));
    var viewW=Math.max(1,Math.round(image.naturalWidth*viewScale));
    var viewH=Math.max(1,Math.round(image.naturalHeight*viewScale));
    canvas.width=viewW;canvas.height=viewH;
    canvas.style.width=viewW+"px";canvas.style.height=viewH+"px";
    // One scale for both axes. Deriving it per axis would let rounding pull the
    // two apart on extreme aspect ratios and map the selection outside the
    // source image.
    var sourceScale=Math.max(image.naturalWidth/viewW,image.naturalHeight/viewH);
    crop={image:image,viewW:viewW,viewH:viewH,sourceScale:sourceScale,size:0,x:0,y:0};
    resetSelection();
    if(cropper)cropper.hidden=false;
    if(cancel)cancel.hidden=false;
    if(reset)reset.hidden=false;
    message(text("messageCropHint"),"");
  };
  var closeCropper=function(){
    crop=null;
    if(cropper)cropper.hidden=true;
    if(cancel)cancel.hidden=true;
    if(reset)reset.hidden=true;
  };

  // Render the selected square at up to the target dimension, never upscaling
  // beyond the pixels the source actually has.
  var renderCrop=function(){
    return new Promise(function(resolve){
      if(!crop||!canvas)return resolve(null);
      // Map the selection back to source pixels and keep it inside the image:
      // a half-pixel of rounding must never become an out-of-bounds read.
      var sourceSide=Math.min(
        crop.size*crop.sourceScale,
        crop.image.naturalWidth,
        crop.image.naturalHeight
      );
      var sx=Math.max(0,Math.min(crop.image.naturalWidth-sourceSide,crop.x*crop.sourceScale));
      var sy=Math.max(0,Math.min(crop.image.naturalHeight-sourceSide,crop.y*crop.sourceScale));
      var side=Math.max(1,Math.round(Math.min(dimension,sourceSide)));
      var output=document.createElement("canvas");
      output.width=side;output.height=side;
      var context=output.getContext("2d");
      if(!context)return resolve(null);
      context.drawImage(crop.image,sx,sy,sourceSide,sourceSide,0,0,side,side);
      var encode=function(type,quality){
        return new Promise(function(resolveBlob){output.toBlob(resolveBlob,type,quality)});
      };
      encode("image/webp",0.9).then(function(blob){
        if(blob&&blob.type==="image/webp")return blob;
        return encode("image/jpeg",0.9);
      }).then(function(blob){
        if(!blob)return resolve(null);
        resolve(new File([blob],blob.type==="image/webp"?"avatar.webp":"avatar.jpg",{type:blob.type}));
      }).catch(function(){resolve(null)});
    });
  };

  if(canvas&&canvasReady){
    var mode=null;var pointer=null;var grabX=0;var grabY=0;var anchorX=0;var anchorY=0;
    var toCanvas=function(event){
      var rect=canvas.getBoundingClientRect();
      var scaleX=canvas.width/(rect.width||canvas.width);
      var scaleY=canvas.height/(rect.height||canvas.height);
      return [(event.clientX-rect.left)*scaleX,(event.clientY-rect.top)*scaleY];
    };
    var hitHandle=function(px,py){
      var found=-1;
      corners().forEach(function(corner,index){
        if(Math.abs(px-corner[0])<=HANDLE&&Math.abs(py-corner[1])<=HANDLE)found=index;
      });
      return found;
    };
    var cursorFor=function(px,py){
      var handle=hitHandle(px,py);
      if(handle===0||handle===3)return "nwse-resize";
      if(handle===1||handle===2)return "nesw-resize";
      if(px>=crop.x&&px<=crop.x+crop.size&&py>=crop.y&&py<=crop.y+crop.size)return "move";
      return "crosshair";
    };
    // Resize from a fixed opposite corner, keeping the selection square by
    // taking the larger of the two axis deltas.
    var resizeFrom=function(px,py){
      var side=Math.max(Math.abs(px-anchorX),Math.abs(py-anchorY));
      var limitX=px<anchorX?anchorX:crop.viewW-anchorX;
      var limitY=py<anchorY?anchorY:crop.viewH-anchorY;
      side=Math.min(Math.max(minSide(),Math.min(side,limitX,limitY)),Math.min(crop.viewW,crop.viewH));
      crop.x=px<anchorX?anchorX-side:anchorX;
      crop.y=py<anchorY?anchorY-side:anchorY;
      crop.size=side;
      clampSelection();draw();
    };
    canvas.addEventListener("pointerdown",function(event){
      if(!crop)return;
      var point=toCanvas(event);
      var handle=hitHandle(point[0],point[1]);
      pointer=event.pointerId;
      if(handle>=0){
        mode="resize";
        var opposite=corners()[3-handle];
        anchorX=opposite[0];anchorY=opposite[1];
      }else if(point[0]>=crop.x&&point[0]<=crop.x+crop.size&&point[1]>=crop.y&&point[1]<=crop.y+crop.size){
        mode="move";grabX=point[0]-crop.x;grabY=point[1]-crop.y;
      }else{
        // Starting outside draws a fresh selection from that corner.
        mode="resize";anchorX=point[0];anchorY=point[1];
        crop.x=point[0];crop.y=point[1];crop.size=minSide();
      }
      if(canvas.setPointerCapture)canvas.setPointerCapture(event.pointerId);
      event.preventDefault();
    });
    canvas.addEventListener("pointermove",function(event){
      if(!crop)return;
      var point=toCanvas(event);
      if(!mode||event.pointerId!==pointer){canvas.style.cursor=cursorFor(point[0],point[1]);return}
      if(mode==="move"){
        crop.x=point[0]-grabX;crop.y=point[1]-grabY;clampSelection();draw();
      }else{
        resizeFrom(point[0],point[1]);
      }
    });
    var endDrag=function(event){
      if(event.pointerId!==pointer)return;
      mode=null;pointer=null;
      if(canvas.releasePointerCapture&&canvas.hasPointerCapture&&canvas.hasPointerCapture(event.pointerId))canvas.releasePointerCapture(event.pointerId);
    };
    canvas.addEventListener("pointerup",endDrag);
    canvas.addEventListener("pointercancel",endDrag);
    canvas.addEventListener("keydown",function(event){
      if(!crop)return;
      var step=event.shiftKey?20:4;
      var moves={ArrowLeft:[-step,0],ArrowRight:[step,0],ArrowUp:[0,-step],ArrowDown:[0,step]};
      var move=moves[event.key];
      if(move){crop.x+=move[0];crop.y+=move[1];clampSelection();draw();event.preventDefault();return}
      if(event.key==="+"||event.key==="="){crop.size+=step;clampSelection();draw();event.preventDefault()}
      else if(event.key==="-"||event.key==="_"){crop.size-=step;clampSelection();draw();event.preventDefault()}
    });
  }
  if(reset)reset.addEventListener("click",function(){resetSelection()});
  if(cancel){
    cancel.addEventListener("click",function(){
      closeCropper();input.value="";message("");
    });
  }

  input.addEventListener("change",function(){
    message("");
    closeCropper();
    var file=input.files&&input.files[0];
    if(!file)return;
    if(file.type&&file.type.indexOf("image/")!==0){
      message(text("messageUnsupported"),"error");
      input.value="";
      return;
    }
    if(maxBytes&&file.size>maxBytes*8){
      // Far beyond anything a crop could rescue; say so before decoding it.
      message(text("messageTooLarge"),"error");
      input.value="";
      return;
    }
    if(!canvasReady){showPreview(file);return}
    var image=new Image();
    var url=URL.createObjectURL(file);
    image.onload=function(){URL.revokeObjectURL(url);openCropper(image)};
    image.onerror=function(){URL.revokeObjectURL(url);message(text("messageUnsupported"),"error");input.value=""};
    image.src=url;
  });

  form.addEventListener("submit",function(event){
    event.preventDefault();
    if(busy)return;
    var file=input.files&&input.files[0];
    if(!file){message(text("messageMissing"),"error");return}
    setBusy(true);
    message(text("messagePreparing"),"");
    var prepare=crop?renderCrop():Promise.resolve(null);
    prepare.then(function(rendered){
      var prepared=rendered||file;
      if(maxBytes&&prepared.size>maxBytes){
        setBusy(false);
        message(text("messageTooLarge"),"error");
        return;
      }
      showPreview(prepared);
      message(text("messageUploading"),"");
      var body=new FormData();
      var csrf=form.querySelector('[name="csrf_token"]');
      body.set("csrf_token",csrf?csrf.value:"");
      body.set("avatar",prepared,prepared.name||"avatar");
      return fetch(form.action,{method:"POST",headers:{accept:"application/json"},body:body,credentials:"same-origin"}).then(function(response){
        return response.json().catch(function(){return {}}).then(function(payload){
          setBusy(false);
          if(response.ok&&payload.ok){
            message(text("messageSaved"),"ok");
            if(payload.picture_url)showPreview(payload.picture_url);
            input.value="";
            closeCropper();
            if(removeForm)removeForm.hidden=false;
            return;
          }
          var key={avatar_too_large:"messageTooLarge",avatar_unsupported:"messageUnsupported",avatar_missing:"messageMissing",avatar_rate_limited:"messageRateLimited",invalid:"messageInvalid"}[payload.error];
          message(text(key||"messageFailed"),"error");
        });
      });
    }).catch(function(){
      setBusy(false);
      message(text("messageFailed"),"error");
    });
  });
})();`

export const FORMS_BROWSER_SCRIPT = `
(function(){
  var clipboard=navigator.clipboard;
  if(clipboard&&typeof clipboard.writeText==="function"){
    document.querySelectorAll("[data-copy-value]").forEach(function(button){
      button.hidden=false;
      button.addEventListener("click",function(){
        var root=button.closest(".copy-value");var source=root&&root.querySelector("[data-copy-source]");var status=root&&root.querySelector("[data-copy-status]");
        if(!source)return;
        clipboard.writeText(source.textContent||"").then(function(){if(status){status.textContent=button.dataset.copySuccess||"";status.hidden=false}});
      });
    });
  }
  document.querySelectorAll("[data-uppercase]").forEach(function(input){
    input.addEventListener("input",function(){var pos=input.selectionStart;var upper=input.value.toUpperCase();if(upper!==input.value){input.value=upper;try{input.setSelectionRange(pos,pos)}catch(e){}}});
  });
  document.querySelectorAll("[data-user-setup-form]").forEach(function(form){
    var region=form.querySelector("[data-user-password-region]");
    var sync=function(){var mode=form.querySelector('[name="setup_mode"]:checked');if(region)region.hidden=!!mode&&mode.value==="invite"};
    form.addEventListener("change",function(event){if(event.target&&event.target.name==="setup_mode")sync()});sync();
  });
  var storage;try{storage=window.sessionStorage}catch(error){}
  var eligible=function(field){return field.name&&field.type!=="password"&&field.type!=="file"&&field.type!=="hidden"&&field.name!=="confirmation"&&field.name!=="csrf_token"&&field.name!=="token"&&field.name!=="client_secret"};
  var serialize=function(form){var values={};Array.from(form.elements).filter(eligible).forEach(function(field){if((field.type==="checkbox"||field.type==="radio")&&!field.checked)return;if(field.tagName==="SELECT"&&field.multiple){Array.from(field.selectedOptions).forEach(function(option){if(values[field.name]===undefined)values[field.name]=[];values[field.name].push(option.value||"")});return}var value=field.value||"";if(values[field.name]===undefined)values[field.name]=[];values[field.name].push(value)});return values};
  var restore=function(form,values){Object.keys(values).forEach(function(name){var fields=Array.from(form.elements).filter(function(field){return field.name===name&&eligible(field)});fields.forEach(function(field){if(field.type==="checkbox"||field.type==="radio")field.checked=values[name].includes(field.value);else if(field.tagName==="SELECT"&&field.multiple)Array.from(field.options).forEach(function(option){option.selected=values[name].includes(option.value)});else field.value=values[name][0]||""})})};
  document.querySelectorAll("[data-draft-clear]").forEach(function(marker){if(storage)try{storage.removeItem(marker.dataset.draftClear)}catch(error){}});
  document.querySelectorAll("[data-draft-form]").forEach(function(container){var form=container.matches("form")?container:container.querySelector("form");var key=container.dataset.draftKey;if(!form||!key||!storage)return;if(new URLSearchParams(window.location.search).get("draft")==="1")try{var saved=JSON.parse(storage.getItem(key)||"null");if(saved)restore(form,saved)}catch(error){};var save=function(){try{storage.setItem(key,JSON.stringify(serialize(form)))}catch(error){}};form.addEventListener("input",save);form.addEventListener("change",save);var passwordMode=form.querySelector('[name="setup_mode"][value="password"]:checked');var note=form.querySelector("[data-password-draft-note]");if(passwordMode&&note)note.hidden=false;container.querySelectorAll("a[href]").forEach(function(link){link.dataset.draftCancel=key})});
  document.querySelectorAll("[data-draft-cancel]").forEach(function(link){link.addEventListener("click",function(){if(storage)try{storage.removeItem(link.dataset.draftCancel)}catch(error){}})});
  document.querySelectorAll("[data-group-request-form]").forEach(function(form){
    var input=form.querySelector("[data-group-request-input]");
    var suggestions=Array.from(form.querySelectorAll("[data-group-request-suggestion]"));
    var empty=form.querySelector("[data-group-request-empty]");
    var count=form.querySelector("[data-group-request-count]");
    if(!input)return;
    var normalize=function(value){try{return (value||"").normalize("NFKD").toLowerCase()}catch(error){return (value||"").toLowerCase()}};
    var render=function(){var term=normalize(input.value.trim());var shown=0;suggestions.forEach(function(suggestion){var groupName=suggestion.dataset.groupName||"";var match=!term||normalize(suggestion.dataset.search||groupName).includes(term);suggestion.hidden=!match;if(match)shown+=1;suggestion.setAttribute("aria-pressed",input.value===groupName?"true":"false")});if(empty)empty.hidden=shown!==0;if(count)count.textContent=String(shown)};
    suggestions.forEach(function(suggestion){suggestion.addEventListener("click",function(){input.value=suggestion.dataset.groupName||"";input.dispatchEvent(new Event("input",{bubbles:true}));input.dispatchEvent(new Event("change",{bubbles:true}));input.focus()})});
    input.addEventListener("input",render);render();
  });
  document.querySelectorAll("[data-search-picker]").forEach(function(root){
    var select=root.querySelector("[data-search-picker-select],select.search-picker__native");
    var query=root.querySelector("[data-search-picker-query]");
    var results=root.querySelector("[data-search-picker-results]");
    var selections=root.querySelector("[data-search-picker-selected]");
    var resultsEmpty=root.querySelector("[data-search-picker-results-empty]");
    var selectedEmpty=root.querySelector("[data-search-picker-selected-empty]");
    var resultsLabel=root.querySelector("[data-search-picker-results-label]");
    var resultsCount=root.querySelector("[data-search-picker-results-count]");
    var selectedCount=root.querySelector("[data-search-picker-selected-count]");
    if(!select||!query||!results||!selections)return;
    var options=Array.from(select.options);var max=Math.max(0,Number(root.dataset.maxSelections)||0);
    var normalize=function(value){try{return (value||"").normalize("NFKD").toLowerCase()}catch(error){return (value||"").toLowerCase()}};
    var clear=function(node){while(node.firstChild)node.removeChild(node.firstChild)};
    var copy=function(option){
      var body=document.createElement("span");body.className="search-picker__copy";
      var title=document.createElement("strong");title.textContent=option.dataset.title||option.textContent||option.value;body.appendChild(title);
      if(option.dataset.detail){var detail=document.createElement("small");detail.textContent=option.dataset.detail;body.appendChild(detail)}
      if(option.dataset.meta){var meta=document.createElement("small");meta.className="mono";meta.textContent=option.dataset.meta;body.appendChild(meta)}
      return body;
    };
    var emit=function(){select.dispatchEvent(new Event("change",{bubbles:true}))};
    var renderSelected=function(){
      clear(selections);var selected=options.filter(function(option){return option.selected});
      selected.forEach(function(option){
        var item=document.createElement("div");item.className="search-picker__selection";item.appendChild(copy(option));
        if(!option.disabled){var remove=document.createElement("button");remove.type="button";remove.className="search-picker__remove";remove.textContent=root.dataset.removeLabel||"Remove";remove.setAttribute("aria-label",(root.dataset.removeLabel||"Remove")+" "+(option.dataset.title||option.textContent||option.value));
        remove.addEventListener("click",function(){option.selected=false;emit();query.focus()});item.appendChild(remove)}selections.appendChild(item);
      });
      if(selectedEmpty)selectedEmpty.hidden=selected.length!==0;
      if(selectedCount)selectedCount.textContent=(root.dataset.countLabel||"{count} selected").replace("{count}",String(selected.length));
    };
    var renderResults=function(){
      clear(results);var term=normalize(query.value.trim());var available=options.filter(function(option){return !option.selected&&!option.disabled});
      var matches=term?available.filter(function(option){return normalize(option.dataset.search||option.textContent||option.value).includes(term)}):available.filter(function(option){return option.dataset.recommended==="1"});
      if(!term&&!matches.length)matches=available;
      var shown=matches.slice(0,8);var selectedTotal=options.filter(function(option){return option.selected&&!option.disabled}).length;var capped=max>0&&selectedTotal>=max;
      shown.forEach(function(option){
        var button=document.createElement("button");button.type="button";button.className="search-picker__option";button.setAttribute("role","option");button.appendChild(copy(option));
        var verb=document.createElement("span");verb.className="search-picker__verb";verb.textContent=root.dataset.addLabel||"Add";button.appendChild(verb);button.disabled=capped;
        button.setAttribute("aria-label",(root.dataset.addLabel||"Add")+" "+(option.dataset.title||option.textContent||option.value));
        button.addEventListener("click",function(){if(capped)return;option.selected=true;query.value="";emit();query.focus()});results.appendChild(button);
      });
      if(resultsLabel)resultsLabel.textContent=term?(root.dataset.resultsLabel||"Search results"):(root.dataset.recommendedLabel||"Recommended");
      if(resultsCount)resultsCount.textContent=String(matches.length);
      if(resultsEmpty)resultsEmpty.hidden=shown.length!==0;
      query.setAttribute("aria-expanded",shown.length===0?"false":"true");
    };
    var render=function(){renderSelected();renderResults()};
    query.addEventListener("input",renderResults);
    query.addEventListener("keydown",function(event){if(event.key!=="Enter")return;event.preventDefault();var first=results.querySelector("button:not([disabled])");if(first)first.click()});
    select.addEventListener("change",render);
    select.addEventListener("invalid",function(event){event.preventDefault();query.focus();query.setAttribute("aria-invalid","true");query.setAttribute("placeholder",root.dataset.requiredMessage||query.getAttribute("placeholder")||"")});
    root.dataset.pickerReady="1";render();
  });
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
    var initial=Math.max(0,Math.min(Number(form.dataset.initialStep)||0,panels.length-1));var current=initial;
    var labels={application:form.dataset.labelApplication||"",device:form.dataset.labelDevice||"",service:form.dataset.labelService||"",public:form.dataset.labelPublic||"",confidential:form.dataset.labelConfidential||""};
    var valueFor=function(name){
      var fields=Array.from(form.querySelectorAll('[name="'+name+'"]'));
      if(!fields.length)return "—";
      if(fields[0].type==="checkbox"){
        var values=fields.filter(function(field){return field.checked}).map(function(field){return (field.value||"").trim()}).filter(Boolean);
        return values.join("\\n")||"—";
      }
      if(fields[0].tagName==="SELECT"&&fields[0].multiple){
        var selectedValues=Array.from(fields[0].selectedOptions).map(function(option){return (option.value||"").trim()}).filter(Boolean);
        return selectedValues.join("\\n")||"—";
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
    var resourceSelect=form.querySelector('select[name="allowed_resources"]');
    var resourceOptions=resourceSelect?Array.from(resourceSelect.options):[];
    var redirect=form.querySelector('[name="redirect_uris"]');
    var logoutRedirect=form.querySelector('[name="post_logout_redirect_uris"]');
    var grants=form.querySelector('[name="allowed_grant_types"]');
    var scopes=form.querySelector('[name="allowed_scopes"]');
    var defaultResource=form.querySelector('[name="default_resource"]');
    var syncResourceRequirement=function(){
      if(resourceSelect)resourceSelect.required=!resourceOptions.some(function(option){return option.selected});
    };
    var syncDefaultResource=function(){
      if(!defaultResource)return;
      var selected=resourceOptions.filter(function(option){return option.selected});
      if(!selected.some(function(option){return option.value===defaultResource.value}))defaultResource.value=selected[0]?selected[0].value:"";
    };
    var syncKindRequirements=function(kind){if(redirect)redirect.required=kind==="application"};
    var suggestResource=function(requiredScopes){
      var candidate=resourceOptions.find(function(option){
        var offered=(option.dataset.resourceScopes||"").split(/\\s+/).filter(Boolean);
        return requiredScopes.every(function(scope){return offered.includes(scope)});
      });
      if(!candidate)return;
      resourceOptions.forEach(function(option){option.selected=option===candidate});
      if(resourceSelect)resourceSelect.dispatchEvent(new Event("change",{bubbles:true}));
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
    form.dataset.wizardReady="1";show(initial);updateReview();var summary=form.querySelector("[data-error-summary]");if(summary)summary.focus();
  });
  document.querySelectorAll("[data-permission-rule-editor]").forEach(function(root){
    var list=root.querySelector("[data-permission-rule-list]");
    var area=root.querySelector("[data-permission-rule-json]");
    var addRule=root.querySelector("[data-permission-rule-add]");
    var applyJson=root.querySelector("[data-permission-rule-apply-json]");
    if(!list||!area||!addRule||!applyJson)return;
    var catalog;try{catalog=JSON.parse(root.dataset.catalog||"{}")}catch(error){return}
    var rules;try{rules=JSON.parse(area.value||"[]")}catch(error){return}
    if(!Array.isArray(rules))return;
    var label=function(name,fallback){return root.dataset[name]||fallback};
    var firstField=function(){return ["application","api","scope"].find(function(field){return Array.isArray(catalog[field])&&catalog[field].length})||"application"};
    var firstValue=function(field){var items=Array.isArray(catalog[field])?catalog[field]:[];return items[0]?items[0].value:""};
    var freshLeaf=function(){var field=firstField();return {field:field,operator:"equals",value:firstValue(field)}};
    var freshGroup=function(operator){return {operator:operator,conditions:[freshLeaf()]}};
    var operatorItems=[{value:"equals",label:"="},{value:"not_equals",label:"!="},{value:"in",label:"IN"},{value:"not_in",label:"NOT IN"}];
    var isSetOperator=function(operator){return operator==="in"||operator==="not_in"};
    var button=function(text,className){var item=document.createElement("button");item.type="button";item.className=className||"btn btn--ghost btn--tiny btn--auto";item.textContent=text;return item};
    var select=function(items,value){var field=document.createElement("select");field.className="input input--compact";items.forEach(function(item){var option=document.createElement("option");option.value=item.value;option.textContent=item.label;option.selected=item.value===value;field.appendChild(option)});return field};
    var normalize=function(value){try{return (value||"").normalize("NFKD").toLowerCase()}catch(error){return (value||"").toLowerCase()}};
    var comboSequence=0;
    var searchableValue=function(items,value,field,onSelect){
      comboSequence+=1;
      var combo=document.createElement("div");combo.className="permission-rule-combobox";combo.dataset.permissionRuleCombobox="";
      var input=document.createElement("input");input.type="search";input.className="input";input.autocomplete="off";input.spellcheck=false;input.setAttribute("role","combobox");input.setAttribute("aria-autocomplete","list");input.setAttribute("aria-expanded","false");
      var listbox=document.createElement("div");listbox.className="permission-rule-combobox__menu";listbox.id="permission-rule-options-"+String(comboSequence);listbox.setAttribute("role","listbox");listbox.hidden=true;input.setAttribute("aria-controls",listbox.id);
      var placeholder=field==="application"?label("searchApplicationLabel","Search applications by name or client ID"):field==="api"?label("searchApiLabel","Search APIs by name or resource URI"):label("searchScopeLabel","Search scopes");
      input.placeholder=placeholder;input.setAttribute("aria-label",placeholder);
      var selected=items.find(function(item){return item.value===value})||null;var dirty=false;
      var itemText=function(item){return item.detail?item.label+" — "+item.detail:item.label===item.value?item.value:item.label+" — "+item.value};
      var restore=function(){input.value=selected?itemText(selected):value||"";dirty=false};restore();
      var shown=[];var active=-1;
      var setActive=function(index){
        var options=Array.from(listbox.querySelectorAll("[data-permission-rule-combobox-option]"));
        active=shown.length?Math.max(0,Math.min(index,shown.length-1)):-1;
        options.forEach(function(option,optionIndex){var current=optionIndex===active;option.classList.toggle("is-active",current);option.setAttribute("aria-selected",current?"true":"false")});
        var activeOption=options[active];if(activeOption){input.setAttribute("aria-activedescendant",activeOption.id);var optionTop=activeOption.offsetTop;var optionBottom=optionTop+activeOption.offsetHeight;var viewportTop=listbox.scrollTop;var viewportBottom=viewportTop+listbox.clientHeight;if(optionTop<viewportTop)listbox.scrollTop=optionTop;else if(optionBottom>viewportBottom)listbox.scrollTop=Math.max(0,optionBottom-listbox.clientHeight)}else input.removeAttribute("aria-activedescendant");
      };
      var choose=function(item){selected=item;input.value=itemText(item);dirty=false;onSelect(item.value);close(false)};
      var renderResults=function(term){
        while(listbox.firstChild)listbox.removeChild(listbox.firstChild);
        var query=normalize(term.trim());var matches=items.filter(function(item){return !query||normalize(item.label+" "+item.value+" "+(item.detail||"")).includes(query)});shown=matches.slice(0,40);active=-1;
        var count=document.createElement("div");count.className="permission-rule-combobox__count";count.setAttribute("role","status");count.setAttribute("aria-live","polite");count.textContent=(matches.length>40?label("limitedMatchesLabel","Showing first {shown} of {count} matches"):label("matchesLabel","{count} matches")).replace("{shown}",String(shown.length)).replace("{count}",String(matches.length));listbox.appendChild(count);
        shown.forEach(function(item,index){
          var option=document.createElement("button");option.type="button";option.className="permission-rule-combobox__option";option.id=listbox.id+"-"+String(index);option.dataset.permissionRuleComboboxOption="";option.setAttribute("role","option");option.setAttribute("aria-selected","false");
          var title=document.createElement("strong");title.textContent=item.label;option.appendChild(title);
          if(item.detail){var detail=document.createElement("small");detail.textContent=item.detail;option.appendChild(detail)}
          if(item.label!==item.value){var meta=document.createElement("small");meta.className="mono";meta.textContent=item.value;option.appendChild(meta)}
          option.addEventListener("mouseenter",function(){setActive(index)});option.addEventListener("mousedown",function(event){event.preventDefault()});option.addEventListener("click",function(){choose(item)});listbox.appendChild(option);
        });
        if(!shown.length){var empty=document.createElement("p");empty.className="permission-rule-combobox__empty";empty.textContent=label("noMatchesLabel","No matches found.");listbox.appendChild(empty)}
      };
      var open=function(term){combo.dataset.open="";listbox.hidden=false;input.setAttribute("aria-expanded","true");renderResults(term)};
      var close=function(shouldRestore){delete combo.dataset.open;listbox.hidden=true;input.setAttribute("aria-expanded","false");input.removeAttribute("aria-activedescendant");active=-1;if(shouldRestore)restore()};
      input.addEventListener("focus",function(){input.select();open("")});
      input.addEventListener("click",function(){if(!combo.hasAttribute("data-open")){input.select();open("")}});
      input.addEventListener("input",function(){dirty=true;open(input.value)});
      input.addEventListener("keydown",function(event){
        if(event.key==="ArrowDown"||event.key==="ArrowUp"){event.preventDefault();if(!combo.hasAttribute("data-open"))open("");setActive(active<0?(event.key==="ArrowDown"?0:shown.length-1):active+(event.key==="ArrowDown"?1:-1));return}
        if(event.key==="Enter"&&combo.hasAttribute("data-open")){event.preventDefault();var item=shown[active>=0?active:dirty?0:-1];if(item)choose(item);else close(true);return}
        if(event.key==="Escape"&&combo.hasAttribute("data-open")){event.preventDefault();close(true);input.select()}
      });
      combo.addEventListener("focusout",function(){setTimeout(function(){if(!combo.contains(document.activeElement))close(true)},0)});
      if(!items.length){input.disabled=true;input.value=""}
      combo.appendChild(input);combo.appendChild(listbox);return combo;
    };
    var searchableValues=function(items,values,field,onSelect){
      comboSequence+=1;
      var selected=Array.from(new Set(Array.isArray(values)?values:[]));
      var combo=document.createElement("div");combo.className="permission-rule-combobox permission-rule-multiselect";combo.dataset.permissionRuleCombobox="";combo.dataset.permissionRuleMultiselect="";
      var control=document.createElement("div");control.className="input permission-rule-multiselect__control";
      var chips=document.createElement("div");chips.className="permission-rule-multiselect__chips";control.appendChild(chips);
      var input=document.createElement("input");input.type="search";input.className="permission-rule-multiselect__search";input.autocomplete="off";input.spellcheck=false;input.setAttribute("role","combobox");input.setAttribute("aria-autocomplete","list");input.setAttribute("aria-expanded","false");
      var listbox=document.createElement("div");listbox.className="permission-rule-combobox__menu";listbox.id="permission-rule-options-"+String(comboSequence);listbox.setAttribute("role","listbox");listbox.setAttribute("aria-multiselectable","true");listbox.hidden=true;input.setAttribute("aria-controls",listbox.id);
      var placeholder=field==="application"?label("searchApplicationLabel","Search applications by name or client ID"):field==="api"?label("searchApiLabel","Search APIs by name or resource URI"):label("searchScopeLabel","Search scopes");
      input.placeholder=placeholder;input.setAttribute("aria-label",placeholder);
      var itemText=function(item){return item.detail?item.label+" — "+item.detail:item.label===item.value?item.value:item.label+" — "+item.value};
      var shown=[];var active=-1;
      var emit=function(){onSelect(selected.slice())};
      var renderChips=function(){
        while(chips.firstChild)chips.removeChild(chips.firstChild);
        selected.forEach(function(value){
          var item=items.find(function(candidate){return candidate.value===value})||{value:value,label:value+" (unavailable)"};
          var chip=button(itemText(item),"permission-rule-multiselect__chip");chip.setAttribute("aria-label",label("removeLabel","Remove")+" "+itemText(item));chip.disabled=selected.length===1;
          var mark=document.createElement("span");mark.setAttribute("aria-hidden","true");mark.textContent="×";chip.appendChild(mark);
          chip.addEventListener("click",function(){if(selected.length===1)return;selected=selected.filter(function(current){return current!==value});renderChips();emit();if(document.activeElement===input)open(input.value)});chips.appendChild(chip);
        });
      };
      var setActive=function(index){
        var options=Array.from(listbox.querySelectorAll("[data-permission-rule-combobox-option]"));active=shown.length?Math.max(0,Math.min(index,shown.length-1)):-1;
        options.forEach(function(option,optionIndex){var current=optionIndex===active;option.classList.toggle("is-active",current);option.setAttribute("aria-selected",current?"true":"false")});
        var activeOption=options[active];if(activeOption){input.setAttribute("aria-activedescendant",activeOption.id);var optionTop=activeOption.offsetTop;var optionBottom=optionTop+activeOption.offsetHeight;var viewportTop=listbox.scrollTop;var viewportBottom=viewportTop+listbox.clientHeight;if(optionTop<viewportTop)listbox.scrollTop=optionTop;else if(optionBottom>viewportBottom)listbox.scrollTop=Math.max(0,optionBottom-listbox.clientHeight)}else input.removeAttribute("aria-activedescendant");
      };
      var choose=function(item){if(selected.indexOf(item.value)<0&&selected.length<64){selected.push(item.value);renderChips();emit()}input.value="";open("");input.focus()};
      var renderResults=function(term){
        while(listbox.firstChild)listbox.removeChild(listbox.firstChild);
        var query=normalize(term.trim());var matches=items.filter(function(item){return selected.indexOf(item.value)<0&&(!query||normalize(item.label+" "+item.value+" "+(item.detail||"")).includes(query))});shown=matches.slice(0,40);active=-1;
        var count=document.createElement("div");count.className="permission-rule-combobox__count";count.setAttribute("role","status");count.setAttribute("aria-live","polite");count.textContent=(matches.length>40?label("limitedMatchesLabel","Showing first {shown} of {count} matches"):label("matchesLabel","{count} matches")).replace("{shown}",String(shown.length)).replace("{count}",String(matches.length));listbox.appendChild(count);
        shown.forEach(function(item,index){var option=document.createElement("button");option.type="button";option.className="permission-rule-combobox__option";option.id=listbox.id+"-"+String(index);option.dataset.permissionRuleComboboxOption="";option.setAttribute("role","option");option.setAttribute("aria-selected","false");var title=document.createElement("strong");title.textContent=item.label;option.appendChild(title);if(item.detail){var detail=document.createElement("small");detail.textContent=item.detail;option.appendChild(detail)}if(item.label!==item.value){var meta=document.createElement("small");meta.className="mono";meta.textContent=item.value;option.appendChild(meta)}option.addEventListener("mouseenter",function(){setActive(index)});option.addEventListener("mousedown",function(event){event.preventDefault()});option.addEventListener("click",function(){choose(item)});listbox.appendChild(option)});
        if(!shown.length){var empty=document.createElement("p");empty.className="permission-rule-combobox__empty";empty.textContent=label("noMatchesLabel","No matches found.");listbox.appendChild(empty)}
      };
      var open=function(term){combo.dataset.open="";listbox.hidden=false;input.setAttribute("aria-expanded","true");renderResults(term)};
      var close=function(){delete combo.dataset.open;listbox.hidden=true;input.setAttribute("aria-expanded","false");input.removeAttribute("aria-activedescendant");active=-1};
      input.addEventListener("focus",function(){open(input.value)});input.addEventListener("click",function(){if(!combo.hasAttribute("data-open"))open(input.value)});input.addEventListener("input",function(){open(input.value)});
      input.addEventListener("keydown",function(event){if(event.key==="ArrowDown"||event.key==="ArrowUp"){event.preventDefault();if(!combo.hasAttribute("data-open"))open(input.value);setActive(active<0?(event.key==="ArrowDown"?0:shown.length-1):active+(event.key==="ArrowDown"?1:-1));return}if(event.key==="Enter"&&combo.hasAttribute("data-open")){event.preventDefault();var item=shown[active>=0?active:0];if(item)choose(item);return}if(event.key==="Escape"&&combo.hasAttribute("data-open")){event.preventDefault();close();input.select();return}if(event.key==="Backspace"&&!input.value&&selected.length>1){selected.pop();renderChips();emit()}});
      combo.addEventListener("focusout",function(){setTimeout(function(){if(!combo.contains(document.activeElement))close()},0)});
      if(!items.length){input.disabled=true}renderChips();control.appendChild(input);combo.appendChild(control);combo.appendChild(listbox);return combo;
    };
    var sync=function(){area.value=JSON.stringify(rules,null,2);area.setCustomValidity("");area.dispatchEvent(new Event("input",{bubbles:true}))};
    var render=function(){
      while(list.firstChild)list.removeChild(list.firstChild);
      var renderCondition=function(condition,replace,remove){
        var node=document.createElement("div");
        var isLeaf=condition&&typeof condition==="object"&&typeof condition.field==="string";
        node.className="permission-rule-node permission-rule-node--"+(isLeaf?"leaf":"group");
        var kind=isLeaf?"condition":condition&&condition.operator==="or"?"or":"and";
        var kindSelect=select([{value:"condition",label:label("conditionLabel","Condition")},{value:"and",label:"AND"},{value:"or",label:"OR"}],kind);
        kindSelect.classList.add("permission-rule-node__kind");
        kindSelect.setAttribute("aria-label",label("conditionLabel","Condition"));
        kindSelect.addEventListener("change",function(){replace(kindSelect.value==="condition"?freshLeaf():freshGroup(kindSelect.value));sync();render()});
        node.appendChild(kindSelect);
        if(isLeaf){
          var fieldSelect=select([{value:"application",label:"application"},{value:"api",label:"api"},{value:"scope",label:"scope"}],condition.field);
          fieldSelect.classList.add("permission-rule-node__field");node.appendChild(fieldSelect);
          if(!operatorItems.some(function(item){return item.value===condition.operator}))condition.operator="equals";
          var operatorSelect=select(operatorItems,condition.operator);operatorSelect.classList.add("permission-rule-node__operator");operatorSelect.setAttribute("aria-label","Operator");
          node.appendChild(operatorSelect);
          var valueSlot=document.createElement("div");valueSlot.className="permission-rule-node__value";node.appendChild(valueSlot);
          var renderLeafValue=function(){
            while(valueSlot.firstChild)valueSlot.removeChild(valueSlot.firstChild);
            var values=Array.isArray(catalog[condition.field])?catalog[condition.field].slice():[];
            if(isSetOperator(condition.operator)){
              var selectedValues=Array.isArray(condition.values)?condition.values.slice():[];
              selectedValues.slice().reverse().forEach(function(value){if(!values.some(function(item){return item.value===value})&&value)values.unshift({value:value,label:value+" (unavailable)"})});
              valueSlot.appendChild(searchableValues(values,selectedValues,condition.field,function(next){condition.values=next;sync()}));
            }else{
              var selectedValue=typeof condition.value==="string"?condition.value:firstValue(condition.field);condition.value=selectedValue;
              if(!values.some(function(item){return item.value===selectedValue})&&selectedValue){values.unshift({value:selectedValue,label:selectedValue+" (unavailable)"})}
              valueSlot.appendChild(searchableValue(values,selectedValue,condition.field,function(next){condition.value=next;sync()}));
            }
          };
          fieldSelect.addEventListener("change",function(){condition.field=fieldSelect.value;var initial=firstValue(condition.field);if(isSetOperator(condition.operator)){condition.values=initial?[initial]:[];delete condition.value}else{condition.value=initial;delete condition.values}sync();renderLeafValue()});
          operatorSelect.addEventListener("change",function(){var next=operatorSelect.value;if(isSetOperator(next)){var selectedValues=Array.isArray(condition.values)?condition.values.slice():condition.value?[condition.value]:[];condition.operator=next;condition.values=Array.from(new Set(selectedValues));delete condition.value}else{var selectedValue=typeof condition.value==="string"?condition.value:Array.isArray(condition.values)&&condition.values.length?condition.values[0]:firstValue(condition.field);condition.operator=next;condition.value=selectedValue;delete condition.values}sync();renderLeafValue()});
          renderLeafValue();
        }else{
          var children=document.createElement("div");children.className="permission-rule-node__children";
          var conditionList=Array.isArray(condition.conditions)?condition.conditions:[];
          condition.conditions=conditionList;
          conditionList.forEach(function(child,index){children.appendChild(renderCondition(child,function(next){conditionList[index]=next},conditionList.length>1?function(){conditionList.splice(index,1);sync();render()}:null))});
          var add=button(label("addConditionLabel","Add condition"));add.addEventListener("click",function(){conditionList.push(freshLeaf());sync();render()});children.appendChild(add);node.appendChild(children);
        }
        if(remove){var removeButton=button(label("removeLabel","Remove"));removeButton.classList.add("permission-rule-node__remove");removeButton.addEventListener("click",function(){remove();sync();render()});node.appendChild(removeButton)}
        return node;
      };
      rules.forEach(function(rule,index){
        var card=document.createElement("section");card.className="permission-rule-card";
        var head=document.createElement("div");head.className="permission-rule-card__head";
        var title=document.createElement("strong");title.textContent=label("ruleLabel","Rule")+" "+String(index+1);head.appendChild(title);
        var effect=select([{value:"allow",label:"allow"},{value:"deny",label:"deny"}],rule.effect==="deny"?"deny":"allow");effect.addEventListener("change",function(){rule.effect=effect.value;sync()});head.appendChild(effect);
        var removeRule=button(label("removeLabel","Remove"),"btn btn--danger btn--tiny btn--auto");removeRule.addEventListener("click",function(){rules.splice(index,1);sync();render()});head.appendChild(removeRule);card.appendChild(head);
        if(!rule.condition)rule.condition=freshGroup("and");
        card.appendChild(renderCondition(rule.condition,function(next){rule.condition=next;sync();render()},null));list.appendChild(card);
      });
      if(!rules.length){var empty=document.createElement("p");empty.className="wizard-empty";empty.textContent=label("emptyLabel","No rules configured. Access is denied by default.");list.appendChild(empty)}
    };
    addRule.addEventListener("click",function(){rules.push({effect:"allow",condition:freshGroup("and")});sync();render()});
    applyJson.addEventListener("click",function(){try{var parsed=JSON.parse(area.value||"[]");if(!Array.isArray(parsed))throw new Error("rules must be an array");rules=parsed;area.setCustomValidity("");render()}catch(error){area.setCustomValidity("Invalid rule JSON");area.reportValidity()}});
    area.addEventListener("input",function(){area.setCustomValidity("")});
    root.dataset.ruleEditorReady="1";render();
  });
})();`
