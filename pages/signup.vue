<template>
	<div class="container">
		<div>
			<img
				src="../static/oppia.io_logo_oranssi.png"
				alt="Oppia.io"
				width="260"
				height="90"
			/>
			<!-- TODO: add signup form -->
			<div class="submit">
				<a class="button">
					Rekisteröidy
				</a>
			</div>
		</div>
	</div>
</template>

<style>
.submit .button {
	display: inline-block;
	border-radius: 4px;
	border: 1px solid #ffffff;
	color: #ffffff;
	text-decoration: none;
	padding: 10px 30px;
}

.submit .button:hover {
	color: var(--color-main);
	background-color: #ffffff;
}

.submit {
	padding-top: 15px;
}
</style>

<script>
export default {
	layout: 'login'
}
</script>
