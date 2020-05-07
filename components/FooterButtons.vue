<template>
	<div class="footer">
		<b-button v-b-toggle.sidebar-contents pill class="contents btn-primary">
			<b-icon icon="book" />
		</b-button>
		<b-button
			v-b-toggle.sidebar-progress
			pill
			class="task-progress btn-primary"
		>
			<b-icon icon="kanban" />
		</b-button>
	</div>
</template>

<style scoped>
.footer {
	position: absolute;
	bottom: 1rem;
	width: 100vw;
}

.btn.contents {
	float: left;
}

.btn.task-progress {
	float: right;
}
</style>

<script>
export default {
	name: 'FooterButtons'
}
</script>
