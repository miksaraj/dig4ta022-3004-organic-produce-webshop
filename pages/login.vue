<template>
	<div class="container">
		<div>
			<img
				src="../static/oppia.io_logo_oranssi.png"
				alt="Oppia.io"
				width="520"
				height="180"
			/>
			<h1 class="title">
				learn, succeed, repeat
			</h1>
			<!-- TODO: add login form -->
			<div class="links">
				<a href="https://nuxtjs.org/" target="_blank" class="button">
					Kirjaudu
				</a>
				<nuxt-link to="/signup" class="button">Rekisteröidy</nuxt-link>
			</div>
		</div>
	</div>
</template>

<script>
export default {
	layout: 'login'
}
</script>

<style>
.title {
	display: block;
	font-weight: 300;
	font-size: 46px;
	color: #ffffff;
	letter-spacing: 1px;
}

.links {
	padding-top: 15px;
}

.button {
	display: inline-block;
	border-radius: 4px;
	border: 1px solid #ffffff;
	color: #ffffff;
	text-decoration: none;
	padding: 10px 30px;
}

.button:hover {
	color: var(--color-main);
	background-color: #ffffff;
}
</style>
