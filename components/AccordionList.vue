<template>
	<div role="tablist">
		<div v-for="item in items" :key="item.id">
			<accordion-card :item="item" :type="type" />
		</div>
	</div>
</template>

<script>
import AccordionCard from '~/components/AccordionCard.vue'
export default {
	name: 'AccordionList',
	components: {
		AccordionCard
	},
	computed: {
		items() {
			return this.$attrs.items
		},
		type() {
			return this.$route.name === 'index' ? 'chapters' : 'sections'
		}
	}
}
</script>
