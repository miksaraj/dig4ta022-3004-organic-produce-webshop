<template>
	<div>
		<options-row :type="type" />
		<card-deck v-if="view === 'cards'" :items="items" />
		<accordion-list v-if="view === 'list'" :items="items" />
	</div>
</template>

<script>
import CardDeck from '~/components/CardDeck.vue'
import OptionsRow from '~/components/OptionsRow.vue'
import AccordionList from '~/components/AccordionList.vue'
export default {
	components: {
		CardDeck,
		OptionsRow,
		AccordionList
	},
	data() {
		return {
			type: 'courses'
		}
	},
	computed: {
		items() {
			return this.$store.state.courses.list
		},
		view() {
			return this.$store.state.settings.coursesView
		}
	}
}
</script>
