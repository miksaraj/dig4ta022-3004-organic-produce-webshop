<template>
	<b-navbar sticky toggleable>
		<b-navbar-brand>Oppia.io</b-navbar-brand>
		<b-navbar-toggle target="navbar-toggle-collapse">
			<template v-slot:default="{ expanded }">
				<b-icon v-if="expanded" icon="x-circle" />
				<b-icon v-else icon="grid" />
			</template>
		</b-navbar-toggle>
		<b-collapse id="navbar-toggle-collapse" is-nav>
			<b-navbar-nav class="ml-auto">
				<b-nav-item>Linkki 1</b-nav-item>
				<b-nav-item>Linkki 2</b-nav-item>
				<b-nav-item>Linkki 3</b-nav-item>
			</b-navbar-nav>
		</b-collapse>
	</b-navbar>
</template>

<script>
export default {
	name: 'navbar'
}
</script>
