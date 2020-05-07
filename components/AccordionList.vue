<template>
	<div role="tablist">
		<div v-for="item in items" :key="item.id">
			<accordion-card :item="item" />
		</div>
	</div>
</template>

<script>
import AccordionCard from '~/components/AccordionCard.vue'
export default {
	name: 'accordionList',
	components: {
		AccordionCard
	},
	computed: {
		items() {
			return this.$attrs.items
		}
	}
}
</script>
