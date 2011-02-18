var packages_loading_html = '<div style="width: 100%; margin-left: auto; margin-right: auto; text-align: center; margin-top: 40px; margin-bottom: 40px"><img border="0" src="/images/packages/wait.gif" alt="please wait" /></div>';

if(!document.getElementsByClass) document.getElementsByClass = function(className) {
    for(var r = [], e = document.getElementsByTagName("*"), i = 0, j = e.length; i < j; i++) r.push(e[i]);
    return r.filter(function(e){return e.className.split(" ").some(function(n){return n===className})});
};

function show_alert(mytitle,mytext) {
    sexy = new SexyAlertBox();
    sexy.alert("<h1>"+mytitle+"</h1>"+mytext);
}

function show_error(mytitle,mytext) {
    sexy = new SexyAlertBox();
    sexy.error("<h1>"+mytitle+"</h1>"+mytext);
}

function show_info(mytitle,mytext) {
    sexy = new SexyAlertBox();
    sexy.info("<h1>"+mytitle+"</h1>"+mytext);
}

function show_confirm(mytitle,mytext,cb) {
    sexy = new SexyAlertBox();
    sexy.confirm("<h1>"+mytitle+"</h1>"+mytext, {onComplete: cb});
}

function show_input_box(mytitle, mytext, prefix, cb) {
    sexy = new SexyAlertBox();
    sexy.prompt("<h1>"+mytitle+"</h1>"+mytext, prefix, {onComplete: cb});
}

function show_select_box(mytitle, mytext, options, cb) {
    sexy = new SexyAlertBox();
    sexy.select("<h1>"+mytitle+"</h1>"+mytext, options, {onComplete: cb});
}

function check_textarea_maxlength(elem) {
    max_len = elem.getAttribute('maxlength');
    cur_len = elem.value.length;
    if (cur_len > max_len) {
        text_data = elem.value;
        elem.value = text_data.substring(0,max_len);
    }
}

function inItem(item) {
    item.style.cursor = "pointer";
}
function outItem(item) {
    item.style.cursor = "default";
}

function string_startswith(s,pattern) {
    return s.indexOf(pattern) === 0;
}

function string_endswith(s,pattern) {
    var d = s.length - pattern.length;
    return d >= 0 && s.lastIndexOf(pattern) === d;
}


function do_login(form_name,dest_div) {
    completeAHAH.likeSubmit('/connect', 'POST', form_name, dest_div);
}

function do_logout_get(dest_div) {
    completeAHAH.ahah('/logout', dest_div, null, 'get', null);

}

function do_logout(form_name,dest_div) {
    completeAHAH.likeSubmit('/logout', 'POST', form_name, dest_div);
}

function set_text_on_element(elem_id,error) {
    document.getElementById(elem_id).innerHTML = error;
}

function div_toggle_slide(div_id) {
    mydiv = document.getElementById(div_id);

    mydisp = mydiv.style.display;
    visible = true;
    if (mydisp == 'none') { visible = false; };
    if (visible) {
        mydiv.style.display = 'none';
    } else {
        mydiv.style.display = '';
    }
}

function image_resize(which, max) {
  var elem = document.getElementById(which);
  if (max == undefined) max = 100;
  if (elem.width > elem.height) {
    if (elem.width > max) elem.width = max;
  } else {
    if (elem.height > max) elem.height = max;
  }
}

function reset_field(obj, val) {
    if (obj.value == val) {
        obj.value = "";
    }
}