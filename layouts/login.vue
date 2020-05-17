<template>
	<div>
		<nuxt />
	</div>
</template>

<style scoped>
.container {
	margin: 0 0;
	min-height: 100vh;
	min-width: 100vw;
	display: flex;
	justify-content: center;
	align-items: center;
	text-align: center;
	background-color: var(--color-main);
}

*,
*:before,
*:after {
	box-sizing: border-box;
	margin: 0;
}

@media screen and (max-width: 520px) {
	.container {
		width: 100vh;
	}
}
</style>
