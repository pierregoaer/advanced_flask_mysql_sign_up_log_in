(() => {
    'use strict'

    // Fetch all the forms we want to apply custom Bootstrap validation styles to
    const forms = document.querySelectorAll('.needs-validation')
    const password = document.querySelector('#password')
    const confirmPassword = document.querySelector('#confirm_password')
    const currentPassword = document.querySelector('#current_password')
    const newPassword = document.querySelector('#new_password')
    const confirmNewPassword = document.querySelector('#confirm_new_password')

    // Loop over them and prevent submission
    Array.from(forms).forEach(form => {
        // Checks for matching passwords on each input
        form.addEventListener('keyup', event => {
            if (form.name === "signUp") {
                confirmPassword.setCustomValidity(confirmPassword.value !== password.value ? "Passwords do not match." : "")
            }
            if (form.name === "updatePassword") {
                confirmNewPassword.setCustomValidity(confirmNewPassword.value !== newPassword.value ? "Passwords do not match." : "")
            }
        })

        form.addEventListener('submit', event => {
            console.log(form.name)
            if (!form.checkValidity()) {
                // console.log(password.value, confirmPassword.value)
                event.preventDefault()
                event.stopPropagation()
            }

            form.classList.add('was-validated')
        }, false)
    })
})()
