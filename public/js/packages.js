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
        if (title_cont.length < 5) {
            show_error('${_("What about the title?")}','${_("Please insert a proper title")}');
            return false;
        }
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

