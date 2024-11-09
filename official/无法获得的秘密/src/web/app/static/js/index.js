async function doSubmit() {
    const formElem = document.getElementById("file-form");
    const formData = new FormData(formElem);
    const response = await fetch("/submit", {
        method: "POST",
        body: formData
    });
    if (response.ok) {
        const data = await response.json();
        const resultElem = document.getElementById("info-toast-body");
        resultElem.innerText = data.flag;
        const infoToast = new bootstrap.Toast(document.getElementById("info-toast"));
        infoToast.show();
    } else {
        const errToast = new bootstrap.Toast(document.getElementById("error-toast"));
        errToast.show();
    }
}

$(document).ready(function() {
    $("#file-form").submit(function(e) {
        e.preventDefault();
        doSubmit();
    });
});