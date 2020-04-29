<template>
	<div>
		<options-row :type="type" />
		<card-deck v-if="view === 'cards'" :items="items" />
		<accordion-list v-if="view === 'list'" :items="items" />
	</div>
</template>

<script>
import OptionsRow from '~/components/OptionsRow.vue'
import CardDeck from '~/components/CardDeck.vue'
import AccordionList from '~/components/AccordionList.vue'
export default {
	components: {
		CardDeck,
		OptionsRow,
		AccordionList
	},
	data() {
		return {
			type: 'modules'
		}
	},
	computed: {
		items() {
			return this.$store.state.modules.list
		},
		view() {
			return this.$store.state.settings.modulesView
		}
	}
}
</script>
