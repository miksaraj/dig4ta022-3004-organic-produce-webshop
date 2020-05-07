<template>
	<div>
		<!-- use fluid instead of fluid="true" (latter gives Vue warning) -->
		<!-- also, I'm turning this to page before merging into master -->
		<b-jumbotron fluid header="Kappaleen otsikko" lead="Alaotsikko">
			<template v-slot:lead>For more information visit website</template>
			<b-button variant="primary" href="#">Tehtävät</b-button>
		</b-jumbotron>
		<b-container fluid="sm">
			<h1>Otsikko</h1>
			<div v-for="item in items" :key="item.order">
				<component :is="contentComponent(item.type)" />
			</div>
		</b-container>
	</div>
</template>

<script>
export default {
	name: 'chapter',
	computed: {
		...mapGetters('contents', ['orderedList']),
		items() {
			// replaced this.$attrs.items with...
			return this.orderedList()
			// ... because no attributes were passed
			// from parent component.
		},
		contentComponent(type) {
			return () => import(`~/components/${type}.vue`)
		}
	}
}
</script>
