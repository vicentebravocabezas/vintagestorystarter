/** @type {import('tailwindcss').Config} */
module.exports = {
	content: ["./**/*.{html,js,templ}"],
	theme: {
		extend: {
			fontFamily: {
				poppins: "Poppins",
			},
		},
	},
	plugins: [require("@tailwindcss/forms")],
};
