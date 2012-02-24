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


function packages_search_more(total, url, target, counter_div, counter_step, self_destroy_div) {
    target_div = document.getElementById(target);
    var started_from = parseInt(document.getElementById(counter_div).innerHTML);
    var cnt_step = parseInt(document.getElementById(counter_step).innerHTML);
    var total_cnt = parseInt(total);
    started_from = started_from + cnt_step;
    document.getElementById(counter_div).innerHTML = started_from;

    function do_et_complete(valid, resp_txt, resp_code) {
        if ((started_from + cnt_step) >= total_cnt) {
            mydiv = document.getElementById(self_destroy_div);
            mydiv.innerHTML = "";
            mydiv.style.display = 'none';
        }
    }

    // create new div
    newdiv = document.createElement('div');
    real_target_div = 'packages-results-more-inside-' + started_from;
    newdiv.setAttribute('id', real_target_div);
    target_div.appendChild(newdiv);

    completeAHAH.ahah(url + '&from=' + started_from, real_target_div, null, 'get', null, packages_loading_html, on_complete = do_et_complete);
}


function set_stars_rating(item,elem_prefix,vote) {
    item.style.cursor = "pointer";
    var myvote = parseInt(vote);
    for (i=1; i<=myvote; i++) {
        imgdoc = document.getElementById(elem_prefix+i);
        if (imgdoc) {
            imgdoc.src = '/images/packages/star_selected.png';
        }
    }
    for (i=myvote+1; i<=5; i++) {
        imgdoc = document.getElementById(elem_prefix+i);
        if (imgdoc) {
            imgdoc.src = '/images/packages/star_empty.png';
        }
    }
}

function reset_stars_rating(item,elem_prefix,vote) {
    item.style.cursor = "default";
    var myvote = parseInt(vote);
    for (i=1; i<=myvote; i++) {
        imgdoc = document.getElementById(elem_prefix+i);
        if (imgdoc) {
            imgdoc.src = '/images/packages/star.png';
        }
    }
    for (i=myvote+1; i<=5; i++) {
        imgdoc = document.getElementById(elem_prefix+i);
        if (imgdoc) {
            imgdoc.src = '/images/packages/star_empty.png';
        }
    }
}

function submit_ugc_vote(pkgkey,user_id,vote,login_url,dest_div) {
    if (user_id == "0") {
        show_alert('${_("User Generated Content")}', '${_("<p>You need to login to make your vote count.</p>")}')
        return;
    }
    completeAHAH.ahah('/packages/vote?vote=' + vote + '&pkgkey=' + pkgkey, dest_div, null, 'get', null);
}

var ugc_new_doc_counter = 0;
function ugc_send_document(form_name,dest_div,div_error,title_id,ugc_count_class,ugc_score_class) {

    title_cont = document.getElementById(title_id).value;
    dest_div_obj = document.getElementById(dest_div);
    err_obj = document.getElementById(div_error);
    form_obj = document.getElementById(form_name);

    function do_et_complete(response) {
        div_doc = document.getElementById('ugc-new-doc-'+ugc_new_doc_counter);
        if (string_startswith(response.toLowerCase(), '${_("Error").lower()}') || string_startswith(response.toLowerCase(),"internal server error")) {
            if (div_doc) {
                dest_div_obj.removeChild(div_doc);
                ugc_new_doc_counter -= 1;
            }
            err_obj.innerHTML = response;
        } else {
            err_obj.innerHTML = '';
            div_doc.innerHTML = response;
            docs_count_elems = document.getElementsByClass(ugc_count_class);
            for (idx = 0; idx < docs_count_elems.length; idx++) {
                cur_val = docs_count_elems[idx].innerHTML;
                cur_val = parseInt(cur_val);
                docs_count_elems[idx].innerHTML = cur_val + 1;
            }
            docs_score_elems = document.getElementsByClass(ugc_score_class);
            max_score = 0;
            for (idx = 0; idx < docs_score_elems.length; idx++) {
                cur_val = docs_score_elems[idx].innerHTML;
                cur_val = parseInt(cur_val);
                if (cur_val > max_score) { max_score = cur_val; }
            }
            for (idx = 0; idx < docs_score_elems.length; idx++) {
                docs_score_elems[idx].innerHTML = max_score;
            }
        }
    }

    function do_et_start() {
        ugc_new_doc_counter += 1;
        newdiv = document.createElement('div');
        newdiv.setAttribute('id', 'ugc-new-doc-'+ugc_new_doc_counter);
        dest_div_obj.appendChild(newdiv);
        completeAHAH.creaDIV('ugc-new-doc-'+ugc_new_doc_counter,packages_loading_html);
        return true;
    }

    return AIM.submit(form_obj, {'onStart' : do_et_start, 'onComplete' : do_et_complete});

}

function delete_ugc_doc(iddoc,err_div,dest_div) {
    err_obj = document.getElementById(err_div);
    dest_obj = document.getElementById(dest_div);

    function do_et_complete(valid, resp_txt, resp_code) {
        if ((!valid) || (string_startswith(resp_txt.toLowerCase(),'${_("Error").lower()}'))) {
            err_obj.innerHTML = resp_txt;
        } else {
            dest_obj.innerHTML = '';
            dest_obj.className = "";
            err_obj.innerHTML = resp_txt;
        }
    }

    function do_et(valid) {
        if (valid) {
            completeAHAH.ahah('/packages/ugc_delete?iddoc=' + iddoc, err_div, null, 'get', null, packages_loading_html, on_complete = do_et_complete);
        }
    }

    show_confirm('${_("Are you sure?")}','${_("You want to <b>remove</b> this document, are you super sure?")}',do_et)

}

function ugc_select_doctype(select_elem, pkgkey, atom, mytitle, keywords, desc, repoid, product, arch, dest_div) {
    ugc_doctype = select_elem.value;
    title_cont = document.getElementById(mytitle).value;
    keywords_cont = document.getElementById(keywords).value;
    desc_cont = document.getElementById(desc).value;
    completeAHAH.ahah('/packages/show_ugc_add?ugc_doctype=' + ugc_doctype + '&pkgkey=' + pkgkey + '&atom=' + atom + '&repoid=' + repoid + '&product=' + product + '&arch=' + arch + '&title=' + title_cont + '&keywords=' + keywords_cont + '&description=' + desc_cont, dest_div, null, 'get', null, packages_loading_html);
}
